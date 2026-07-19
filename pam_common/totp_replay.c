#define _GNU_SOURCE

#include "totp_replay.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#define RUNTIME_PARENT "/run"
#define STATE_DIRECTORY "pam-totp-lab"
#define MAX_MODULE_TAG_LEN 32U
#define STATE_NAME_SIZE 96U
#define COUNTER_DIGITS 20U
#define COUNTER_RECORD_SIZE (COUNTER_DIGITS + 1U)
#define TEMP_NAME_SIZE 160U

struct totp_replay_transaction {
    int directory_fd;
    int lock_fd;
    int state_fd;
    uid_t expected_owner;
    char state_name[STATE_NAME_SIZE];
    uint64_t stored_counter;
    int has_counter;
    int poisoned;
};

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

static int random_nonce(uint64_t *nonce_out)
{
    unsigned char *cursor = (unsigned char *)nonce_out;
    size_t total = 0U;

    if (nonce_out == NULL) return -1;
    while (total < sizeof(*nonce_out)) {
        ssize_t count = getrandom(cursor + total, sizeof(*nonce_out) - total,
                                  0U);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (count == 0) return -1;
        total += (size_t)count;
    }
    return 0;
}

static int replace_counter_record(
    struct totp_replay_transaction *transaction, uint64_t counter)
{
    char temporary[TEMP_NAME_SIZE];
    uint64_t nonce = UINT64_C(0);
    int temporary_fd = -1;
    int replacement_fd = -1;
    int formatted;
    int renamed = 0;
    int result = -1;

    memset(temporary, 0, sizeof(temporary));
    if (random_nonce(&nonce) != 0) goto cleanup;
    formatted = snprintf(temporary, sizeof(temporary), ".%s-%016" PRIx64 ".tmp",
                         transaction->state_name, nonce);
    nonce = UINT64_C(0);
    if (formatted < 0 || (size_t)formatted >= sizeof(temporary)) goto cleanup;

    temporary_fd = openat(transaction->directory_fd, temporary,
                          O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC |
                              O_NONBLOCK,
                          (mode_t)0600);
    if (temporary_fd < 0 ||
        validate_regular_file(temporary_fd, transaction->expected_owner) != 0 ||
        write_counter_record(temporary_fd, counter) != 0) {
        goto cleanup;
    }
    if (close(temporary_fd) != 0) {
        temporary_fd = -1;
        goto cleanup;
    }
    temporary_fd = -1;

    if (renameat(transaction->directory_fd, temporary,
                 transaction->directory_fd, transaction->state_name) != 0) {
        goto cleanup;
    }
    renamed = 1;
    if (fsync(transaction->directory_fd) != 0) goto cleanup;

    replacement_fd = openat(
        transaction->directory_fd, transaction->state_name,
        O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (replacement_fd < 0 ||
        validate_regular_file(replacement_fd, transaction->expected_owner) !=
            0) {
        goto cleanup;
    }
    if (transaction->state_fd >= 0) close(transaction->state_fd);
    transaction->state_fd = replacement_fd;
    replacement_fd = -1;
    result = 0;

cleanup:
    if (temporary_fd >= 0) close(temporary_fd);
    if (replacement_fd >= 0) close(replacement_fd);
    if (!renamed && temporary[0] != '\0') {
        (void)unlinkat(transaction->directory_fd, temporary, 0);
    }
    memset(temporary, 0, sizeof(temporary));
    return result;
}

static void close_transaction(struct totp_replay_transaction *transaction)
{
    if (transaction == NULL) return;
    if (transaction->state_fd >= 0) close(transaction->state_fd);
    if (transaction->lock_fd >= 0) close(transaction->lock_fd);
    if (transaction->directory_fd >= 0) close(transaction->directory_fd);
    memset(transaction, 0, sizeof(*transaction));
    free(transaction);
}

static int begin_transaction_at(int state_dir_fd, uid_t expected_owner,
                                const char *module_tag, uid_t user_id,
                                int nonblocking,
                                struct totp_replay_transaction **out)
{
    struct totp_replay_transaction *transaction = NULL;
    char lock_name[STATE_NAME_SIZE];
    int ignored_created = 0;
    int formatted;
    int result = TOTP_REPLAY_ERROR;
    struct stat state_stat;

    if (out == NULL) return TOTP_REPLAY_ERROR;
    *out = NULL;
    if (validate_module_tag(module_tag) != 0 ||
        validate_directory(state_dir_fd, expected_owner, (mode_t)0077) != 0) {
        return TOTP_REPLAY_ERROR;
    }
    formatted = snprintf(lock_name, sizeof(lock_name), "%s-%" PRIuMAX ".lock",
                         module_tag, (uintmax_t)user_id);
    if (formatted < 0 || (size_t)formatted >= sizeof(lock_name)) {
        return TOTP_REPLAY_ERROR;
    }

    transaction = calloc(1U, sizeof(*transaction));
    if (transaction == NULL) return TOTP_REPLAY_ERROR;
    transaction->directory_fd = -1;
    transaction->lock_fd = -1;
    transaction->state_fd = -1;
    transaction->expected_owner = expected_owner;
    formatted = snprintf(transaction->state_name,
                         sizeof(transaction->state_name),
                         "%s-%" PRIuMAX ".counter", module_tag,
                         (uintmax_t)user_id);
    if (formatted < 0 ||
        (size_t)formatted >= sizeof(transaction->state_name)) {
        goto cleanup;
    }
    transaction->directory_fd =
        fcntl(state_dir_fd, F_DUPFD_CLOEXEC, 0);
    if (transaction->directory_fd < 0) goto cleanup;

    transaction->lock_fd = open_private_file_at(
        transaction->directory_fd, lock_name, &ignored_created);
    if (transaction->lock_fd < 0) goto cleanup;
    if (flock(transaction->lock_fd,
              LOCK_EX | (nonblocking ? LOCK_NB : 0)) != 0) {
        if (nonblocking && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            result = TOTP_REPLAY_BUSY;
        }
        goto cleanup;
    }
    if (validate_regular_file(transaction->lock_fd, expected_owner) != 0) {
        goto cleanup;
    }

    transaction->state_fd = openat(
        transaction->directory_fd, transaction->state_name,
        O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (transaction->state_fd < 0) {
        if (errno != ENOENT) goto cleanup;
    } else {
        if (validate_regular_file(transaction->state_fd, expected_owner) != 0 ||
            fstat(transaction->state_fd, &state_stat) != 0) {
            goto cleanup;
        }
        if (state_stat.st_size != (off_t)COUNTER_RECORD_SIZE) goto cleanup;
        if (read_counter_record(transaction->state_fd,
                                &transaction->stored_counter) != 0) {
            goto cleanup;
        }
        transaction->has_counter = 1;
    }

    result = TOTP_REPLAY_ACCEPTED;
    *out = transaction;
    transaction = NULL;

cleanup:
    close_transaction(transaction);
    return result;
}

int totp_replay_transaction_consume(struct totp_replay_transaction *transaction,
                                    uint64_t counter)
{
    if (transaction == NULL || transaction->directory_fd < 0 ||
        transaction->lock_fd < 0 || transaction->poisoned) {
        return TOTP_REPLAY_ERROR;
    }
    if (transaction->has_counter && counter <= transaction->stored_counter) {
        return TOTP_REPLAY_DETECTED;
    }

    if (replace_counter_record(transaction, counter) != 0) {
        transaction->poisoned = 1;
        return TOTP_REPLAY_ERROR;
    }
    transaction->stored_counter = counter;
    transaction->has_counter = 1;
    return TOTP_REPLAY_ACCEPTED;
}

void totp_replay_transaction_end(struct totp_replay_transaction **transaction)
{
    if (transaction == NULL || *transaction == NULL) return;
    close_transaction(*transaction);
    *transaction = NULL;
}

static int check_and_store_at(int state_dir_fd, uid_t expected_owner,
                              const char *module_tag, uid_t user_id,
                              uint64_t counter)
{
    struct totp_replay_transaction *transaction = NULL;
    int result = begin_transaction_at(state_dir_fd, expected_owner, module_tag,
                                      user_id, 0, &transaction);

    if (result == TOTP_REPLAY_ACCEPTED) {
        result = totp_replay_transaction_consume(transaction, counter);
    }
    totp_replay_transaction_end(&transaction);
    return result;
}

static int open_runtime_state_directory(void)
{
    int parent_fd = -1;
    int state_dir_fd = -1;

    parent_fd = open(RUNTIME_PARENT,
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent_fd < 0 ||
        validate_directory(parent_fd, (uid_t)0, (mode_t)0022) != 0) {
        goto cleanup;
    }
    if (mkdirat(parent_fd, STATE_DIRECTORY, (mode_t)0700) != 0 &&
        errno != EEXIST) {
        goto cleanup;
    }
    state_dir_fd = openat(parent_fd, STATE_DIRECTORY,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (state_dir_fd < 0 ||
        validate_directory(state_dir_fd, (uid_t)0, (mode_t)0077) != 0) {
        if (state_dir_fd >= 0) close(state_dir_fd);
        state_dir_fd = -1;
    }

cleanup:
    if (parent_fd >= 0) close(parent_fd);
    return state_dir_fd;
}

int totp_replay_transaction_begin(const char *module_tag, uid_t user_id,
                                  struct totp_replay_transaction **out)
{
    int state_dir_fd;
    int result;

    if (out == NULL) return TOTP_REPLAY_ERROR;
    *out = NULL;
    if (geteuid() != (uid_t)0) return TOTP_REPLAY_ERROR;
    state_dir_fd = open_runtime_state_directory();
    if (state_dir_fd < 0) return TOTP_REPLAY_ERROR;
    result = begin_transaction_at(state_dir_fd, (uid_t)0, module_tag, user_id,
                                  1, out);
    close(state_dir_fd);
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

int totp_replay_transaction_begin_at(
    int state_dir_fd, uid_t expected_owner, const char *module_tag,
    uid_t user_id, struct totp_replay_transaction **out)
{
    return begin_transaction_at(state_dir_fd, expected_owner, module_tag,
                                user_id, 1, out);
}
#endif
