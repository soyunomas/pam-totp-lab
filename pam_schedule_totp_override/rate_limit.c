#define _GNU_SOURCE

#include "rate_limit.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define PSO_RUNTIME_PARENT "/run"
#define PSO_RUNTIME_DIRECTORY "pam-totp-lab"
#define PSO_SERVICE_MAX 32U
#define PSO_RATE_NAME_SIZE 96U
#define PSO_RATE_RECORD_SIZE 53U

struct rate_state {
    uint64_t window_start;
    unsigned int failures;
    uint64_t blocked_until;
};

static int validate_directory(int fd, uid_t owner, mode_t forbidden)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == owner &&
                   (st.st_mode & forbidden) == 0
               ? 0
               : -1;
}

static int validate_state_file(int fd, uid_t owner)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == owner &&
                   st.st_nlink == 1 && (st.st_mode & (mode_t)0777) == (mode_t)0600
               ? 0
               : -1;
}

int pso_validate_service(const char *service)
{
    size_t length;

    if (service == NULL) return -1;
    length = strnlen(service, PSO_SERVICE_MAX + 1U);
    if (length == 0U || length > PSO_SERVICE_MAX) return -1;
    for (size_t i = 0U; i < length; i++) {
        unsigned char ch = (unsigned char)service[i];
        if (!((ch >= (unsigned char)'A' && ch <= (unsigned char)'Z') ||
              (ch >= (unsigned char)'a' && ch <= (unsigned char)'z') ||
              (ch >= (unsigned char)'0' && ch <= (unsigned char)'9') ||
              ch == (unsigned char)'_' || ch == (unsigned char)'-')) {
            return -1;
        }
    }
    return 0;
}

static uint64_t hash_service(const char *service)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    for (size_t i = 0U; service[i] != '\0'; i++) {
        hash ^= (uint64_t)(unsigned char)service[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static int state_name(char *out, size_t capacity, uid_t user_id,
                      const char *service)
{
    int written;

    if (out == NULL || pso_validate_service(service) != 0) return -1;
    written = snprintf(out, capacity, "pso-rate-%" PRIuMAX "-%016" PRIx64 ".state",
                       (uintmax_t)user_id, hash_service(service));
    return written >= 0 && (size_t)written < capacity ? 0 : -1;
}

static int parse_decimal(const char *text, size_t length, uint64_t *value_out)
{
    uint64_t value = 0U;

    if (text == NULL || value_out == NULL || length == 0U) return -1;
    for (size_t i = 0U; i < length; i++) {
        uint64_t digit;
        if (text[i] < '0' || text[i] > '9') return -1;
        digit = (uint64_t)(text[i] - '0');
        if (value > (UINT64_MAX - digit) / UINT64_C(10)) return -1;
        value = value * UINT64_C(10) + digit;
    }
    *value_out = value;
    return 0;
}

static int read_state(int fd, struct rate_state *state)
{
    struct stat st;
    char record[PSO_RATE_RECORD_SIZE];
    size_t total = 0U;
    uint64_t failures;

    memset(state, 0, sizeof(*state));
    if (fstat(fd, &st) != 0) return -1;
    if (st.st_size == (off_t)0) return 0;
    if (st.st_size != (off_t)PSO_RATE_RECORD_SIZE) return -1;

    while (total < sizeof(record)) {
        ssize_t count = pread(fd, record + total, sizeof(record) - total,
                              (off_t)total);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (count == 0) return -1;
        total += (size_t)count;
    }

    if (memcmp(record, "PSO1 ", 5U) != 0 || record[25] != ' ' ||
        record[31] != ' ' || record[52] != '\n' ||
        parse_decimal(record + 5, 20U, &state->window_start) != 0 ||
        parse_decimal(record + 26, 5U, &failures) != 0 || failures > 99999U ||
        parse_decimal(record + 32, 20U, &state->blocked_until) != 0) {
        return -1;
    }
    state->failures = (unsigned int)failures;
    return 0;
}

static int write_state(int fd, const struct rate_state *state)
{
    char record[PSO_RATE_RECORD_SIZE + 1U];
    size_t total = 0U;
    int written;

    written = snprintf(record, sizeof(record),
                       "PSO1 %020" PRIu64 " %05u %020" PRIu64 "\n",
                       state->window_start, state->failures,
                       state->blocked_until);
    if (written != (int)PSO_RATE_RECORD_SIZE) return -1;

    while (total < PSO_RATE_RECORD_SIZE) {
        ssize_t count = pwrite(fd, record + total,
                               PSO_RATE_RECORD_SIZE - total, (off_t)total);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (count == 0) return -1;
        total += (size_t)count;
    }
    if (ftruncate(fd, (off_t)PSO_RATE_RECORD_SIZE) != 0 || fsync(fd) != 0) {
        return -1;
    }
    return 0;
}

static int open_state_locked(int state_dir_fd, uid_t expected_owner,
                             uid_t user_id, const char *service)
{
    char name[PSO_RATE_NAME_SIZE];
    int fd;

    if (validate_directory(state_dir_fd, expected_owner, (mode_t)0077) != 0 ||
        state_name(name, sizeof(name), user_id, service) != 0) {
        return -1;
    }

    fd = openat(state_dir_fd, name,
                O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
                (mode_t)0600);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX) != 0 || validate_state_file(fd, expected_owner) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int pso_rate_check_at(int state_dir_fd, uid_t expected_owner, uid_t user_id,
                      const char *service, uint64_t now)
{
    struct rate_state state;
    int fd = open_state_locked(state_dir_fd, expected_owner, user_id, service);
    int result = PSO_RATE_ERROR;

    if (fd < 0) return PSO_RATE_ERROR;
    if (read_state(fd, &state) != 0) goto cleanup;
    if (state.window_start > now) goto cleanup;
    result = state.blocked_until > now ? PSO_RATE_BLOCKED : PSO_RATE_ALLOWED;

cleanup:
    close(fd);
    return result;
}

int pso_rate_record_failure_at(int state_dir_fd, uid_t expected_owner,
                               uid_t user_id, const char *service,
                               uint64_t now)
{
    struct rate_state state;
    int fd = open_state_locked(state_dir_fd, expected_owner, user_id, service);
    int result = PSO_RATE_ERROR;

    if (fd < 0) return PSO_RATE_ERROR;
    if (read_state(fd, &state) != 0 || state.window_start > now) goto cleanup;

    if (state.blocked_until > now) {
        result = PSO_RATE_BLOCKED;
        goto cleanup;
    }
    if (state.window_start == 0U ||
        now - state.window_start >= PSO_RATE_WINDOW_SECONDS) {
        state.window_start = now;
        state.failures = 1U;
        state.blocked_until = 0U;
    } else {
        if (state.failures >= 99999U) goto cleanup;
        state.failures++;
    }

    if (state.failures >= PSO_RATE_MAX_FAILURES) {
        if (UINT64_MAX - now < PSO_RATE_BLOCK_SECONDS) goto cleanup;
        state.blocked_until = now + PSO_RATE_BLOCK_SECONDS;
        result = PSO_RATE_BLOCKED;
    } else {
        result = PSO_RATE_ALLOWED;
    }
    if (write_state(fd, &state) != 0) result = PSO_RATE_ERROR;

cleanup:
    close(fd);
    return result;
}

int pso_rate_reset_at(int state_dir_fd, uid_t expected_owner, uid_t user_id,
                      const char *service)
{
    struct rate_state state = {0U, 0U, 0U};
    int fd = open_state_locked(state_dir_fd, expected_owner, user_id, service);
    int result;

    if (fd < 0) return PSO_RATE_ERROR;
    result = write_state(fd, &state) == 0 ? PSO_RATE_ALLOWED : PSO_RATE_ERROR;
    close(fd);
    return result;
}

int pso_monotonic_seconds(uint64_t *seconds_out)
{
    struct timespec value;

    if (seconds_out == NULL || clock_gettime(CLOCK_MONOTONIC, &value) != 0 ||
        value.tv_sec < (time_t)0) {
        return -1;
    }
    *seconds_out = (uint64_t)value.tv_sec;
    return 0;
}

static int open_runtime_directory(void)
{
    int parent_fd = -1;
    int state_fd = -1;

    if (geteuid() != (uid_t)0) return -1;
    parent_fd = open(PSO_RUNTIME_PARENT,
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent_fd < 0 ||
        validate_directory(parent_fd, (uid_t)0, (mode_t)0022) != 0) {
        goto cleanup;
    }
    if (mkdirat(parent_fd, PSO_RUNTIME_DIRECTORY, (mode_t)0700) != 0 &&
        errno != EEXIST) {
        goto cleanup;
    }
    state_fd = openat(parent_fd, PSO_RUNTIME_DIRECTORY,
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (state_fd < 0 || validate_directory(state_fd, (uid_t)0,
                                            (mode_t)0077) != 0) {
        if (state_fd >= 0) close(state_fd);
        state_fd = -1;
    }

cleanup:
    if (parent_fd >= 0) close(parent_fd);
    return state_fd;
}

int pso_rate_check(uid_t user_id, const char *service, uint64_t now)
{
    int fd = open_runtime_directory();
    int result;
    if (fd < 0) return PSO_RATE_ERROR;
    result = pso_rate_check_at(fd, (uid_t)0, user_id, service, now);
    close(fd);
    return result;
}

int pso_rate_record_failure(uid_t user_id, const char *service, uint64_t now)
{
    int fd = open_runtime_directory();
    int result;
    if (fd < 0) return PSO_RATE_ERROR;
    result = pso_rate_record_failure_at(fd, (uid_t)0, user_id, service, now);
    close(fd);
    return result;
}

int pso_rate_reset(uid_t user_id, const char *service)
{
    int fd = open_runtime_directory();
    int result;
    if (fd < 0) return PSO_RATE_ERROR;
    result = pso_rate_reset_at(fd, (uid_t)0, user_id, service);
    close(fd);
    return result;
}
