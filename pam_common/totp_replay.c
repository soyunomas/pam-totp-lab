#define _GNU_SOURCE

#include "totp_replay.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define RUNTIME_PARENT "/run"
#define STATE_DIRECTORY "pam-totp-lab"
#define MAX_MODULE_TAG_LEN 32U
#define STATE_NAME_SIZE 96U
#define COUNTER_DIGITS 20U
#define COUNTER_RECORD_SIZE (COUNTER_DIGITS + 1U)

static int validate_module_tag(const char *module_tag)
{
    size_t length;

    if (module_tag == NULL) return -1;
    length = strnlen(module_tag, MAX_MODULE_TAG_LEN + 1U);
    if (length == 0U || length > MAX_MODULE_TAG_LEN) return -1;

    for (size_t i = 0U; i < length; i++) {
        unsigned char ch = (unsigned char)module_tag[i];
        if (!((ch >= (unsigned char)'a' && ch <= (unsigned char)'z') ||
              (ch >= (unsigned char)'0' && ch <= (unsigned char)'9') ||
              ch == (unsigned char)'_' || ch == (unsigned char)'-')) {
            return -1;
        }
    }
    return 0;
}

static int validate_directory(int fd, uid_t expected_owner,
                              mode_t forbidden_permissions)
{
    struct stat st;

    if (fstat(fd, &st) != 0) return -1;
    if (!S_ISDIR(st.st_mode) || st.st_uid != expected_owner ||
        (st.st_mode & forbidden_permissions) != 0) {
        return -1;
    }
    return 0;
}

static int validate_regular_file(int fd, uid_t expected_owner)
{
    struct stat st;

    if (fstat(fd, &st) != 0) return -1;
    if (!S_ISREG(st.st_mode) || st.st_uid != expected_owner ||
        (st.st_mode & (mode_t)0077) != 0 || st.st_nlink != 1) {
        return -1;
    }
    return 0;
}

static int open_private_file_at(int directory_fd, const char *name,
                                int *created_out)
{
    int fd;
    int flags = O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK;

    *created_out = 0;
    fd = openat(directory_fd, name, flags | O_CREAT | O_EXCL, (mode_t)0600);
    if (fd >= 0) {
        *created_out = 1;
        return fd;
    }
    if (errno != EEXIST) return -1;
    return openat(directory_fd, name, flags);
}

static int read_counter_record(int fd, uint64_t *counter_out)
{
    char record[COUNTER_RECORD_SIZE];
    size_t total = 0U;
    uint64_t value = 0U;

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

    if (record[COUNTER_DIGITS] != '\n') return -1;
    for (size_t i = 0U; i < COUNTER_DIGITS; i++) {
        unsigned char ch = (unsigned char)record[i];
        uint64_t digit;

        if (ch < (unsigned char)'0' || ch > (unsigned char)'9') return -1;
        digit = (uint64_t)(ch - (unsigned char)'0');
        if (value > (UINT64_MAX - digit) / UINT64_C(10)) return -1;
        value = value * UINT64_C(10) + digit;
    }

    *counter_out = value;
    return 0;
}

static int write_counter_record(int fd, uint64_t counter)
{
    char record[COUNTER_RECORD_SIZE + 1U];
    int formatted;
    size_t total = 0U;

    formatted = snprintf(record, sizeof(record), "%020" PRIu64 "\n", counter);
    if (formatted != (int)COUNTER_RECORD_SIZE) return -1;

    while (total < COUNTER_RECORD_SIZE) {
        ssize_t count = pwrite(fd, record + total, COUNTER_RECORD_SIZE - total,
                               (off_t)total);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (count == 0) return -1;
        total += (size_t)count;
    }

    if (fsync(fd) != 0) return -1;
    return 0;
}

static int check_and_store_at(int state_dir_fd, uid_t expected_owner,
                              const char *module_tag, uid_t user_id,
                              uint64_t counter)
{
    char lock_name[STATE_NAME_SIZE];
    char state_name[STATE_NAME_SIZE];
    int lock_fd = -1;
    int state_fd = -1;
    int created = 0;
    int ignored_created = 0;
    int result = TOTP_REPLAY_ERROR;
    struct stat state_stat;
    uint64_t stored_counter = 0U;

    if (validate_module_tag(module_tag) != 0 ||
        validate_directory(state_dir_fd, expected_owner, (mode_t)0077) != 0) {
        return TOTP_REPLAY_ERROR;
    }
    if (snprintf(lock_name, sizeof(lock_name), "%s-%" PRIuMAX ".lock",
                 module_tag, (uintmax_t)user_id) >= (int)sizeof(lock_name) ||
        snprintf(state_name, sizeof(state_name), "%s-%" PRIuMAX ".counter",
                 module_tag, (uintmax_t)user_id) >= (int)sizeof(state_name)) {
        return TOTP_REPLAY_ERROR;
    }

    lock_fd = open_private_file_at(state_dir_fd, lock_name, &ignored_created);
    if (lock_fd < 0) goto cleanup;
    if (flock(lock_fd, LOCK_EX) != 0) goto cleanup;
    if (validate_regular_file(lock_fd, expected_owner) != 0) goto cleanup;

    state_fd = open_private_file_at(state_dir_fd, state_name, &created);
    if (state_fd < 0) goto cleanup;
    if (validate_regular_file(state_fd, expected_owner) != 0) goto cleanup;
    if (fstat(state_fd, &state_stat) != 0) goto cleanup;

    if (created && state_stat.st_size == (off_t)0) {
        /* No accepted counter exists yet. */
    } else {
        if (state_stat.st_size != (off_t)COUNTER_RECORD_SIZE) goto cleanup;
        if (read_counter_record(state_fd, &stored_counter) != 0) goto cleanup;
        if (counter <= stored_counter) {
            result = TOTP_REPLAY_DETECTED;
            goto cleanup;
        }
    }

    if (write_counter_record(state_fd, counter) != 0) goto cleanup;
    result = TOTP_REPLAY_ACCEPTED;

cleanup:
    if (state_fd >= 0) close(state_fd);
    if (lock_fd >= 0) close(lock_fd);
    return result;
}

int totp_replay_check_and_store(const char *module_tag, uid_t user_id,
                                uint64_t counter)
{
    int parent_fd = -1;
    int state_dir_fd = -1;
    int result = TOTP_REPLAY_ERROR;

    if (geteuid() != (uid_t)0) return TOTP_REPLAY_ERROR;

    parent_fd = open(RUNTIME_PARENT,
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent_fd < 0) goto cleanup;
    if (validate_directory(parent_fd, (uid_t)0, (mode_t)0022) != 0) {
        goto cleanup;
    }

    if (mkdirat(parent_fd, STATE_DIRECTORY, (mode_t)0700) != 0 &&
        errno != EEXIST) {
        goto cleanup;
    }
    state_dir_fd = openat(parent_fd, STATE_DIRECTORY,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (state_dir_fd < 0) goto cleanup;
    result = check_and_store_at(state_dir_fd, (uid_t)0, module_tag, user_id,
                                counter);

cleanup:
    if (state_dir_fd >= 0) close(state_dir_fd);
    if (parent_fd >= 0) close(parent_fd);
    return result;
}

#ifdef TOTP_REPLAY_TESTING
int totp_replay_check_and_store_at(int state_dir_fd, uid_t expected_owner,
                                   const char *module_tag, uid_t user_id,
                                   uint64_t counter)
{
    return check_and_store_at(state_dir_fd, expected_owner, module_tag, user_id,
                              counter);
}
#endif
