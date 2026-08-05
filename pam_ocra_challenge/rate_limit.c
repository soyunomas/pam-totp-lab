#define _GNU_SOURCE

#include "rate_limit.h"

#include "scope.h"
#include "secret_store.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define RATE_LIMIT_MAX_ATTEMPTS 5U
#define RATE_LIMIT_INTERVAL UINT64_C(300)
#define RATE_LIMIT_RECENT_COUNT 16U
#define RATE_LIMIT_COLLISION_RETRIES 8U
#define RATE_LIMIT_RECORD_SIZE 224U
#define RATE_LIMIT_PAYLOAD_SIZE 220U
#define RATE_LIMIT_STATE_SUFFIX ".state"
#define RATE_LIMIT_LOCK_SUFFIX ".lock"
#define RATE_LIMIT_TEMP_SUFFIX ".tmp"
#define RATE_LIMIT_NAME_MAX                                                    \
    (OCRA_UID_TEXT_MAX_LENGTH + 1U + OCRA_SERVICE_MAX_LENGTH + 1U +           \
     OCRA_KEY_ID_HEX_LENGTH + sizeof(RATE_LIMIT_STATE_SUFFIX))

static const unsigned char rate_limit_magic[8] = {'O', 'C', 'R', 'A',
                                                   'R', 'L', '1', '\0'};

struct rate_limit_state {
    uint64_t sequence;
    uint64_t window_started;
    uint64_t last_seen;
    uint64_t blocked_until;
    uint32_t attempts;
    uint32_t recent_count;
    uint32_t recent_next;
    char recent[RATE_LIMIT_RECENT_COUNT][OCRA_CHALLENGE_DIGITS];
};

static int system_clock(clockid_t clock_id, struct timespec *value)
{
    return clock_gettime(clock_id, value);
}

#ifdef OCRA_TESTING
static ocra_rate_limit_clock_provider clock_provider = system_clock;
static ocra_rate_limit_challenge_provider challenge_provider =
    ocra_generate_challenge;
static ocra_rate_limit_state_close_provider state_close_provider = close;
static uid_t test_expected_uid;
static gid_t test_expected_gid;
static int test_expected_owner_is_set;
#endif

static uid_t expected_uid(void)
{
#ifdef OCRA_TESTING
    return test_expected_owner_is_set != 0 ? test_expected_uid : geteuid();
#else
    return (uid_t)0;
#endif
}

static gid_t expected_gid(void)
{
#ifdef OCRA_TESTING
    return test_expected_owner_is_set != 0 ? test_expected_gid : getegid();
#else
    return (gid_t)0;
#endif
}

static int read_clock(uint64_t *seconds)
{
    struct timespec value;
    int result;

#ifdef OCRA_TESTING
    result = clock_provider(CLOCK_MONOTONIC, &value);
#else
    result = system_clock(CLOCK_MONOTONIC, &value);
#endif
    if (result != 0 || value.tv_sec < (time_t)0 || value.tv_nsec < 0L ||
        value.tv_nsec >= 1000000000L) {
        return -1;
    }
    *seconds = (uint64_t)value.tv_sec;
    if ((time_t)*seconds != value.tv_sec ||
        *seconds > (uint64_t)INT64_MAX - RATE_LIMIT_INTERVAL) {
        *seconds = 0U;
        return -1;
    }
    return 0;
}

static int generate_challenge(char output[OCRA_CHALLENGE_DIGITS + 1U])
{
#ifdef OCRA_TESTING
    return challenge_provider(output);
#else
    return ocra_generate_challenge(output);
#endif
}

static int close_state_file(int fd)
{
#ifdef OCRA_TESTING
    return state_close_provider(fd);
#else
    return close(fd);
#endif
}

static int challenge_is_valid(
    const char challenge[OCRA_CHALLENGE_DIGITS + 1U])
{
    size_t index;

    if (challenge == NULL) {
        return 0;
    }
    for (index = 0U; index < OCRA_CHALLENGE_DIGITS; ++index) {
        if (challenge[index] < '0' || challenge[index] > '9') {
            return 0;
        }
    }
    return challenge[OCRA_CHALLENGE_DIGITS] == '\0';
}

static int key_id_is_valid(const char *key_id)
{
    size_t index;

    if (key_id == NULL) {
        return 0;
    }
    for (index = 0U; index < OCRA_KEY_ID_HEX_LENGTH; ++index) {
        unsigned char byte = (unsigned char)key_id[index];

        if (!((byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              (byte >= (unsigned char)'a' && byte <= (unsigned char)'f') ||
              (byte >= (unsigned char)'A' && byte <= (unsigned char)'F'))) {
            return 0;
        }
    }
    return key_id[OCRA_KEY_ID_HEX_LENGTH] == '\0';
}

static int directory_metadata_is_valid(int fd, int exact_mode)
{
    struct stat status;

    if (fstat(fd, &status) != 0 || !S_ISDIR(status.st_mode) ||
        status.st_uid != expected_uid() || status.st_gid != expected_gid()) {
        return 0;
    }
    if (exact_mode != 0) {
        return (status.st_mode & 07777) == 0700;
    }
    return (status.st_mode & 0022) == 0;
}

static int file_metadata_is_valid(int fd, struct stat *status)
{
    return fstat(fd, status) == 0 && S_ISREG(status->st_mode) &&
           status->st_nlink == 1 && (status->st_mode & 07777) == 0600 &&
           status->st_uid == expected_uid() && status->st_gid == expected_gid();
}

static int normalize_created_object(int fd, mode_t mode)
{
    if (fchown(fd, expected_uid(), expected_gid()) != 0 ||
        fchmod(fd, mode) != 0) {
        return -1;
    }
    return 0;
}

static int path_matches_file(int root_fd, const char *name,
                             const struct stat *file_status)
{
    struct stat path_status;

    return fstatat(root_fd, name, &path_status, AT_SYMLINK_NOFOLLOW) == 0 &&
           S_ISREG(path_status.st_mode) && path_status.st_dev == file_status->st_dev &&
           path_status.st_ino == file_status->st_ino &&
           path_status.st_nlink == 1 &&
           (path_status.st_mode & 07777) == 0600 &&
           path_status.st_uid == expected_uid() &&
           path_status.st_gid == expected_gid();
}

static int lock_exclusive(int fd)
{
    struct flock lock;

    (void)memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    for (;;) {
        if (fcntl(fd, F_SETLKW, &lock) == 0) {
            return 0;
        }
        if (errno != EINTR) {
            return -1;
        }
    }
}

static void store_u32(unsigned char *output, uint32_t value)
{
    output[0] = (unsigned char)(value >> 24U);
    output[1] = (unsigned char)(value >> 16U);
    output[2] = (unsigned char)(value >> 8U);
    output[3] = (unsigned char)value;
}

static uint32_t load_u32(const unsigned char *input)
{
    return ((uint32_t)input[0] << 24U) | ((uint32_t)input[1] << 16U) |
           ((uint32_t)input[2] << 8U) | (uint32_t)input[3];
}

static void store_u64(unsigned char *output, uint64_t value)
{
    size_t index;

    for (index = 0U; index < 8U; ++index) {
        output[index] = (unsigned char)(value >> (56U - (index * 8U)));
    }
}

static uint64_t load_u64(const unsigned char *input)
{
    uint64_t value = 0U;
    size_t index;

    for (index = 0U; index < 8U; ++index) {
        value = (value << 8U) | (uint64_t)input[index];
    }
    return value;
}

static uint32_t crc32_bytes(const unsigned char *data, size_t length)
{
    uint32_t crc = UINT32_MAX;
    size_t index;

    for (index = 0U; index < length; ++index) {
        unsigned int bit;

        crc ^= (uint32_t)data[index];
        for (bit = 0U; bit < 8U; ++bit) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1U);

            crc = (crc >> 1U) ^ (UINT32_C(0xedb88320) & mask);
        }
    }
    return ~crc;
}

static void encode_state(const struct rate_limit_state *state,
                         unsigned char record[RATE_LIMIT_RECORD_SIZE])
{
    size_t index;

    (void)memset(record, 0, RATE_LIMIT_RECORD_SIZE);
    (void)memcpy(record, rate_limit_magic, sizeof(rate_limit_magic));
    store_u32(record + 8U, UINT32_C(1));
    store_u64(record + 12U, state->sequence);
    store_u64(record + 20U, state->window_started);
    store_u64(record + 28U, state->last_seen);
    store_u64(record + 36U, state->blocked_until);
    store_u32(record + 44U, state->attempts);
    store_u32(record + 48U, state->recent_count);
    store_u32(record + 52U, state->recent_next);
    for (index = 0U; index < RATE_LIMIT_RECENT_COUNT; ++index) {
        (void)memcpy(record + 60U + (index * OCRA_CHALLENGE_DIGITS),
                     state->recent[index], OCRA_CHALLENGE_DIGITS);
    }
    store_u32(record + RATE_LIMIT_PAYLOAD_SIZE,
              crc32_bytes(record, RATE_LIMIT_PAYLOAD_SIZE));
}

static int decode_state(const unsigned char record[RATE_LIMIT_RECORD_SIZE],
                        struct rate_limit_state *state)
{
    size_t index;
    uint32_t count;
    uint32_t next;
    uint32_t attempts;

    (void)memset(state, 0, sizeof(*state));
    if (memcmp(record, rate_limit_magic, sizeof(rate_limit_magic)) != 0 ||
        load_u32(record + 8U) != UINT32_C(1) ||
        load_u32(record + RATE_LIMIT_PAYLOAD_SIZE) !=
            crc32_bytes(record, RATE_LIMIT_PAYLOAD_SIZE) ||
        load_u32(record + 56U) != 0U) {
        return -1;
    }
    state->sequence = load_u64(record + 12U);
    state->window_started = load_u64(record + 20U);
    state->last_seen = load_u64(record + 28U);
    state->blocked_until = load_u64(record + 36U);
    attempts = load_u32(record + 44U);
    count = load_u32(record + 48U);
    next = load_u32(record + 52U);
    if (state->sequence == 0U || attempts > RATE_LIMIT_MAX_ATTEMPTS ||
        count > RATE_LIMIT_RECENT_COUNT ||
        (count < RATE_LIMIT_RECENT_COUNT && next != count) ||
        (count == RATE_LIMIT_RECENT_COUNT && next >= RATE_LIMIT_RECENT_COUNT) ||
        state->window_started > (uint64_t)INT64_MAX ||
        state->last_seen > (uint64_t)INT64_MAX ||
        state->blocked_until > (uint64_t)INT64_MAX ||
        (attempts > 0U && state->last_seen < state->window_started) ||
        (attempts < RATE_LIMIT_MAX_ATTEMPTS && state->blocked_until != 0U) ||
        (attempts == RATE_LIMIT_MAX_ATTEMPTS &&
         state->blocked_until < state->last_seen) ||
        (attempts == 0U &&
         (state->window_started != 0U || state->blocked_until != 0U))) {
        return -1;
    }
    state->attempts = attempts;
    state->recent_count = count;
    state->recent_next = next;
    for (index = 0U; index < RATE_LIMIT_RECENT_COUNT; ++index) {
        const unsigned char *source =
            record + 60U + (index * OCRA_CHALLENGE_DIGITS);
        size_t digit;

        if (index < count) {
            for (digit = 0U; digit < OCRA_CHALLENGE_DIGITS; ++digit) {
                if (source[digit] < (unsigned char)'0' ||
                    source[digit] > (unsigned char)'9') {
                    return -1;
                }
            }
            (void)memcpy(state->recent[index], source,
                         OCRA_CHALLENGE_DIGITS);
        } else {
            for (digit = 0U; digit < OCRA_CHALLENGE_DIGITS; ++digit) {
                if (source[digit] != 0U) {
                    return -1;
                }
            }
        }
    }
    return 0;
}

static int read_complete(int fd, unsigned char *data, size_t length)
{
    size_t offset = 0U;

    while (offset < length) {
        ssize_t count = pread(fd, data + offset, length - offset, (off_t)offset);

        if (count > 0) {
            offset += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int write_complete(int fd, const unsigned char *data, size_t length)
{
    size_t offset = 0U;

    while (offset < length) {
        ssize_t count = pwrite(fd, data + offset, length - offset,
                               (off_t)offset);

        if (count > 0) {
            offset += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int load_state_file(int root_fd, const char *state_name,
                           struct rate_limit_state *state, int *state_fd,
                           int allow_missing)
{
    unsigned char record[RATE_LIMIT_RECORD_SIZE];
    struct stat status;
    int fd;

    (void)memset(record, 0, sizeof(record));
    fd = openat(root_fd, state_name,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        if (allow_missing != 0 && errno == ENOENT) {
            (void)memset(state, 0, sizeof(*state));
            *state_fd = -1;
            return 0;
        }
        return -1;
    }
    if (!file_metadata_is_valid(fd, &status) ||
        status.st_size != (off_t)RATE_LIMIT_RECORD_SIZE ||
        !path_matches_file(root_fd, state_name, &status) ||
        read_complete(fd, record, sizeof(record)) != 0 ||
        decode_state(record, state) != 0) {
        (void)close(fd);
        return -1;
    }
    *state_fd = fd;
    return 0;
}

static int remove_valid_stale_temp(int root_fd, const char *temp_name)
{
    struct stat status;
    int fd = openat(root_fd, temp_name,
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);

    if (fd < 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (!file_metadata_is_valid(fd, &status) ||
        !path_matches_file(root_fd, temp_name, &status) ||
        unlinkat(root_fd, temp_name, 0) != 0) {
        (void)close(fd);
        return -1;
    }
    return close(fd) == 0 ? 0 : -1;
}

static int persist_state(int root_fd, const char *state_name,
                         const char *temp_name, int previous_fd,
                         struct rate_limit_state *state)
{
    unsigned char record[RATE_LIMIT_RECORD_SIZE];
    struct stat previous_status;
    struct stat temp_status;
    int temp_fd = -1;
    int temp_exists = 0;
    int result = -1;

    if (state->sequence == UINT64_MAX) {
        return -1;
    }
    if (previous_fd >= 0 &&
        (!file_metadata_is_valid(previous_fd, &previous_status) ||
         !path_matches_file(root_fd, state_name, &previous_status))) {
        return -1;
    }
    if (remove_valid_stale_temp(root_fd, temp_name) != 0) {
        return -1;
    }
    temp_fd = openat(root_fd, temp_name,
                     O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC |
                         O_NONBLOCK,
                     0600);
    if (temp_fd < 0) {
        return -1;
    }
    temp_exists = 1;
    if (temp_exists != 0 &&
        normalize_created_object(temp_fd, (mode_t)0600) != 0) {
        goto cleanup;
    }
    if (!file_metadata_is_valid(temp_fd, &temp_status) ||
        !path_matches_file(root_fd, temp_name, &temp_status)) {
        goto cleanup;
    }
    ++state->sequence;
    encode_state(state, record);
    if (write_complete(temp_fd, record, sizeof(record)) != 0 ||
        ftruncate(temp_fd, (off_t)sizeof(record)) != 0 || fsync(temp_fd) != 0 ||
        !file_metadata_is_valid(temp_fd, &temp_status) ||
        temp_status.st_size != (off_t)sizeof(record) ||
        !path_matches_file(root_fd, temp_name, &temp_status) ||
        renameat(root_fd, temp_name, root_fd, state_name) != 0) {
        --state->sequence;
        goto cleanup;
    }
    temp_exists = 0;
    if (fsync(root_fd) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    (void)memset(record, 0, sizeof(record));
    if (temp_fd >= 0 && close(temp_fd) != 0) {
        result = -1;
    }
    if (temp_exists != 0) {
        (void)unlinkat(root_fd, temp_name, 0);
    }
    return result;
}

static int build_names(const char *uid_text, const char *service,
                       const char *key_id, char state_name[RATE_LIMIT_NAME_MAX],
                       char lock_name[RATE_LIMIT_NAME_MAX],
                       char temp_name[RATE_LIMIT_NAME_MAX])
{
    uid_t uid;
    int state_count;
    int lock_count;
    int temp_count;

    if (ocra_scope_parse_uid(uid_text, &uid) != 0 ||
        ocra_scope_validate_service(service) != 0 ||
        !key_id_is_valid(key_id)) {
        return -1;
    }
    (void)uid;
    state_count = snprintf(state_name, RATE_LIMIT_NAME_MAX, "%s-%s-%s%s",
                           uid_text, service, key_id, RATE_LIMIT_STATE_SUFFIX);
    lock_count = snprintf(lock_name, RATE_LIMIT_NAME_MAX, "%s-%s-%s%s",
                          uid_text, service, key_id, RATE_LIMIT_LOCK_SUFFIX);
    temp_count = snprintf(temp_name, RATE_LIMIT_NAME_MAX, "%s-%s-%s%s",
                          uid_text, service, key_id, RATE_LIMIT_TEMP_SUFFIX);
    return state_count > 0 && (size_t)state_count < RATE_LIMIT_NAME_MAX &&
                   lock_count > 0 && (size_t)lock_count < RATE_LIMIT_NAME_MAX &&
                   temp_count > 0 && (size_t)temp_count < RATE_LIMIT_NAME_MAX
               ? 0
               : -1;
}

static int open_scope_lock(int root_fd, const char *lock_name)
{
    struct stat status;
    int created = 0;
    int fd = openat(root_fd, lock_name,
                    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC |
                        O_NONBLOCK,
                    0600);

    if (fd >= 0) {
        created = 1;
    } else if (errno == EEXIST) {
        fd = openat(root_fd, lock_name,
                    O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    }

    if (fd < 0 ||
        (created != 0 &&
         normalize_created_object(fd, (mode_t)0600) != 0) ||
        !file_metadata_is_valid(fd, &status) ||
        !path_matches_file(root_fd, lock_name, &status) ||
        lock_exclusive(fd) != 0 || !file_metadata_is_valid(fd, &status) ||
        !path_matches_file(root_fd, lock_name, &status)) {
        if (fd >= 0) {
            (void)close(fd);
        }
        return -1;
    }
    return fd;
}

static void add_recent(struct rate_limit_state *state,
                       const char challenge[OCRA_CHALLENGE_DIGITS + 1U])
{
    (void)memcpy(state->recent[state->recent_next], challenge,
                 OCRA_CHALLENGE_DIGITS);
    if (state->recent_count < RATE_LIMIT_RECENT_COUNT) {
        ++state->recent_count;
        state->recent_next = state->recent_count;
        if (state->recent_count == RATE_LIMIT_RECENT_COUNT) {
            state->recent_next = 0U;
        }
    } else {
        state->recent_next =
            (state->recent_next + 1U) % RATE_LIMIT_RECENT_COUNT;
    }
}

static int recent_contains(
    const struct rate_limit_state *state,
    const char challenge[OCRA_CHALLENGE_DIGITS + 1U])
{
    uint32_t index;

    for (index = 0U; index < state->recent_count; ++index) {
        if (memcmp(state->recent[index], challenge, OCRA_CHALLENGE_DIGITS) ==
            0) {
            return 1;
        }
    }
    return 0;
}

static int generate_fresh_challenge(
    const struct rate_limit_state *state,
    char challenge[OCRA_CHALLENGE_DIGITS + 1U])
{
    unsigned int retry;

    for (retry = 0U; retry < RATE_LIMIT_COLLISION_RETRIES; ++retry) {
        if (generate_challenge(challenge) != 0 ||
            !challenge_is_valid(challenge)) {
            return -1;
        }
        if (!recent_contains(state, challenge)) {
            return 0;
        }
    }
    challenge[0] = '\0';
    return -1;
}

static int reserve_locked(int root_fd, const char *state_name,
                          const char *temp_name, uint64_t now,
                          char challenge[OCRA_CHALLENGE_DIGITS + 1U])
{
    struct rate_limit_state state;
    int state_fd = -1;
    int result = -1;

    if (load_state_file(root_fd, state_name, &state, &state_fd, 1) != 0 ||
        now < state.last_seen) {
        goto cleanup;
    }
    if (state.blocked_until != 0U) {
        if (now < state.blocked_until) {
            goto cleanup;
        }
        state.attempts = 0U;
        state.window_started = 0U;
        state.blocked_until = 0U;
    } else if (state.attempts > 0U &&
               now - state.window_started >= RATE_LIMIT_INTERVAL) {
        state.attempts = 0U;
        state.window_started = 0U;
    }
    if (state.attempts >= RATE_LIMIT_MAX_ATTEMPTS ||
        generate_fresh_challenge(&state, challenge) != 0) {
        goto cleanup;
    }
    if (state.attempts == 0U) {
        state.window_started = now;
    }
    ++state.attempts;
    state.last_seen = now;
    if (state.attempts == RATE_LIMIT_MAX_ATTEMPTS) {
        state.blocked_until = now + RATE_LIMIT_INTERVAL;
    }
    add_recent(&state, challenge);
    if (persist_state(root_fd, state_name, temp_name, state_fd, &state) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (state_fd >= 0 && close_state_file(state_fd) != 0) {
        result = -1;
    }
    if (result != 0) {
        challenge[0] = '\0';
    }
    (void)memset(&state, 0, sizeof(state));
    return result;
}

int ocra_rate_limit_reserve_at(
    int root_fd, const char *uid_text, const char *service, const char *key_id,
    char challenge[OCRA_CHALLENGE_DIGITS + 1U])
{
    char state_name[RATE_LIMIT_NAME_MAX];
    char lock_name[RATE_LIMIT_NAME_MAX];
    char temp_name[RATE_LIMIT_NAME_MAX];
    uint64_t now;
    int lock_fd = -1;
    int result = -1;

    if (challenge == NULL) {
        return -1;
    }
    challenge[0] = '\0';
    if (root_fd < 0 || !directory_metadata_is_valid(root_fd, 1) ||
        build_names(uid_text, service, key_id, state_name, lock_name,
                    temp_name) != 0) {
        return -1;
    }
    lock_fd = open_scope_lock(root_fd, lock_name);
    if (lock_fd < 0) {
        return -1;
    }
    if (read_clock(&now) == 0) {
        result = reserve_locked(root_fd, state_name, temp_name, now, challenge);
    }
    if (close(lock_fd) != 0) {
        result = -1;
        challenge[0] = '\0';
    }
    return result;
}

int ocra_rate_limit_reset_at(int root_fd, const char *uid_text,
                             const char *service, const char *key_id)
{
    char state_name[RATE_LIMIT_NAME_MAX];
    char lock_name[RATE_LIMIT_NAME_MAX];
    char temp_name[RATE_LIMIT_NAME_MAX];
    struct rate_limit_state state;
    uint64_t now;
    int lock_fd = -1;
    int state_fd = -1;
    int result = -1;

    (void)memset(&state, 0, sizeof(state));
    if (root_fd < 0 || !directory_metadata_is_valid(root_fd, 1) ||
        build_names(uid_text, service, key_id, state_name, lock_name,
                    temp_name) != 0) {
        return -1;
    }
    lock_fd = open_scope_lock(root_fd, lock_name);
    if (lock_fd < 0) {
        return -1;
    }
    if (read_clock(&now) != 0 ||
        load_state_file(root_fd, state_name, &state, &state_fd, 0) != 0 ||
        now < state.last_seen) {
        goto cleanup;
    }
    state.attempts = 0U;
    state.window_started = 0U;
    state.last_seen = now;
    state.blocked_until = 0U;
    if (persist_state(root_fd, state_name, temp_name, state_fd, &state) == 0) {
        result = 0;
    }

cleanup:
    if (state_fd >= 0 && close(state_fd) != 0) {
        result = -1;
    }
    if (close(lock_fd) != 0) {
        result = -1;
    }
    (void)memset(&state, 0, sizeof(state));
    return result;
}

int ocra_rate_limit_remove_at(int root_fd, const char *uid_text,
                              const char *service, const char *key_id)
{
    char state_name[RATE_LIMIT_NAME_MAX];
    char lock_name[RATE_LIMIT_NAME_MAX];
    char temp_name[RATE_LIMIT_NAME_MAX];
    struct rate_limit_state state;
    int lock_fd = -1;
    int state_fd = -1;
    int result = -1;

    (void)memset(&state, 0, sizeof(state));
    if (root_fd < 0 || !directory_metadata_is_valid(root_fd, 1) ||
        build_names(uid_text, service, key_id, state_name, lock_name,
                    temp_name) != 0) {
        return -1;
    }
    lock_fd = open_scope_lock(root_fd, lock_name);
    if (lock_fd < 0 ||
        load_state_file(root_fd, state_name, &state, &state_fd, 1) != 0 ||
        remove_valid_stale_temp(root_fd, temp_name) != 0) {
        goto cleanup;
    }
    if (state_fd >= 0 && unlinkat(root_fd, state_name, 0) != 0) {
        goto cleanup;
    }
    if (fsync(root_fd) == 0) {
        result = 0;
    }

cleanup:
    if (state_fd >= 0 && close(state_fd) != 0) {
        result = -1;
    }
    if (lock_fd >= 0 && close(lock_fd) != 0) {
        result = -1;
    }
    (void)memset(&state, 0, sizeof(state));
    return result;
}

static int open_or_create_directory(int parent_fd, const char *name)
{
    int created = 0;
    int fd;

    if (mkdirat(parent_fd, name, 0700) == 0) {
        created = 1;
    } else if (errno != EEXIST) {
        return -1;
    }
    fd = openat(parent_fd, name,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 ||
        (created != 0 && normalize_created_object(fd, (mode_t)0700) != 0) ||
        !directory_metadata_is_valid(fd, 1)) {
        if (fd >= 0) {
            (void)close(fd);
        }
        return -1;
    }
    return fd;
}

#ifdef OCRA_TESTING
int ocra_rate_limit_prepare_directory_at_for_tests(int parent_fd,
                                                   const char *name)
{
    int fd = open_or_create_directory(parent_fd, name);

    if (fd < 0) {
        return -1;
    }
    return close(fd) == 0 ? 0 : -1;
}
#endif

static int open_production_root(void)
{
    int slash_fd = -1;
    int run_fd = -1;
    int parent_fd = -1;
    int state_root_fd = -1;

    slash_fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (slash_fd < 0 || !directory_metadata_is_valid(slash_fd, 0)) {
        goto cleanup;
    }
    run_fd = openat(slash_fd, "run",
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (run_fd < 0 || !directory_metadata_is_valid(run_fd, 0)) {
        goto cleanup;
    }
    parent_fd = open_or_create_directory(run_fd, "pam-totp-lab");
    if (parent_fd < 0) {
        goto cleanup;
    }
    state_root_fd = open_or_create_directory(parent_fd, "ocra");

cleanup:
    if (parent_fd >= 0) {
        (void)close(parent_fd);
    }
    if (run_fd >= 0) {
        (void)close(run_fd);
    }
    if (slash_fd >= 0) {
        (void)close(slash_fd);
    }
    return state_root_fd;
}

int ocra_rate_limit_reserve(uid_t uid, const char *service,
                            const char *key_id,
                            char challenge[OCRA_CHALLENGE_DIGITS + 1U])
{
    char uid_text[OCRA_UID_TEXT_MAX_LENGTH + 1U];
    int root_fd;
    int count;
    int result;

    if (challenge == NULL) {
        return -1;
    }
    challenge[0] = '\0';
    count = snprintf(uid_text, sizeof(uid_text), "%" PRIuMAX, (uintmax_t)uid);
    if (count < 0 || (size_t)count >= sizeof(uid_text)) {
        return -1;
    }
    root_fd = open_production_root();
    if (root_fd < 0) {
        return -1;
    }
    result = ocra_rate_limit_reserve_at(root_fd, uid_text, service, key_id,
                                        challenge);
    if (close(root_fd) != 0) {
        result = -1;
        challenge[0] = '\0';
    }
    (void)memset(uid_text, 0, sizeof(uid_text));
    return result;
}

int ocra_rate_limit_reset(uid_t uid, const char *service, const char *key_id)
{
    char uid_text[OCRA_UID_TEXT_MAX_LENGTH + 1U];
    int root_fd;
    int count;
    int result;

    count = snprintf(uid_text, sizeof(uid_text), "%" PRIuMAX, (uintmax_t)uid);
    if (count < 0 || (size_t)count >= sizeof(uid_text)) {
        return -1;
    }
    root_fd = open_production_root();
    if (root_fd < 0) {
        (void)memset(uid_text, 0, sizeof(uid_text));
        return -1;
    }
    result = ocra_rate_limit_reset_at(root_fd, uid_text, service, key_id);
    if (close(root_fd) != 0) {
        result = -1;
    }
    (void)memset(uid_text, 0, sizeof(uid_text));
    return result;
}

int ocra_rate_limit_remove(uid_t uid, const char *service, const char *key_id)
{
    char uid_text[OCRA_UID_TEXT_MAX_LENGTH + 1U];
    int root_fd;
    int count;
    int result;

    count = snprintf(uid_text, sizeof(uid_text), "%" PRIuMAX, (uintmax_t)uid);
    if (count < 0 || (size_t)count >= sizeof(uid_text)) {
        return -1;
    }
    root_fd = open_production_root();
    if (root_fd < 0) {
        (void)memset(uid_text, 0, sizeof(uid_text));
        return -1;
    }
    result = ocra_rate_limit_remove_at(root_fd, uid_text, service, key_id);
    if (close(root_fd) != 0) {
        result = -1;
    }
    (void)memset(uid_text, 0, sizeof(uid_text));
    return result;
}

#ifdef OCRA_TESTING
void ocra_rate_limit_set_clock_provider_for_tests(
    ocra_rate_limit_clock_provider provider)
{
    clock_provider = provider == NULL ? system_clock : provider;
}

void ocra_rate_limit_reset_clock_provider_for_tests(void)
{
    clock_provider = system_clock;
}

void ocra_rate_limit_set_challenge_provider_for_tests(
    ocra_rate_limit_challenge_provider provider)
{
    challenge_provider = provider == NULL ? ocra_generate_challenge : provider;
}

void ocra_rate_limit_reset_challenge_provider_for_tests(void)
{
    challenge_provider = ocra_generate_challenge;
}

void ocra_rate_limit_set_expected_owner_for_tests(uid_t uid, gid_t gid)
{
    test_expected_uid = uid;
    test_expected_gid = gid;
    test_expected_owner_is_set = 1;
}

void ocra_rate_limit_reset_expected_owner_for_tests(void)
{
    test_expected_uid = (uid_t)0;
    test_expected_gid = (gid_t)0;
    test_expected_owner_is_set = 0;
}

void ocra_rate_limit_set_state_close_provider_for_tests(
    ocra_rate_limit_state_close_provider provider)
{
    state_close_provider = provider == NULL ? close : provider;
}

void ocra_rate_limit_reset_state_close_provider_for_tests(void)
{
    state_close_provider = close;
}
#endif
