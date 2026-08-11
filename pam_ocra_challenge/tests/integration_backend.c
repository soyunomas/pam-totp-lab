#define _GNU_SOURCE

#include "../rate_limit.h"
#include "../secret_store.h"
#include "../secure_memory.h"

#include <fcntl.h>
#include <pwd.h>
#include <security/pam_modules.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define INTEGRATION_UID ((uid_t)4242)
#define INTEGRATION_SECOND_UID ((uid_t)4243)
#define INTEGRATION_SCOPE_COUNT 2U

int ocra_integration_fail_delay(pam_handle_t *handle, unsigned int delay)
{
    (void)handle;
    (void)delay;
    return PAM_SUCCESS;
}

static int open_state(void)
{
    const char *path = getenv("OCRA_INTEGRATION_STATE");
    struct stat status;
    int fd;

    if (path == NULL || path[0] != '/') {
        return -1;
    }
    fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_uid != geteuid() || status.st_nlink != 1 ||
        (status.st_mode & 0777) != 0600 ||
        status.st_size !=
            (off_t)(sizeof(uint32_t) * INTEGRATION_SCOPE_COUNT)) {
        if (fd >= 0) {
            (void)close(fd);
        }
        return -1;
    }
    return fd;
}

static int scope_index(uid_t uid, size_t *index)
{
    if (uid == INTEGRATION_UID) {
        *index = 0U;
        return 0;
    }
    if (uid == INTEGRATION_SECOND_UID) {
        *index = 1U;
        return 0;
    }
    return -1;
}

static int reserve_attempt(uid_t uid)
{
    uint32_t attempts[INTEGRATION_SCOPE_COUNT];
    size_t index;
    int fd = open_state();
    int result = -1;

    if (scope_index(uid, &index) != 0 || fd < 0 ||
        flock(fd, LOCK_EX) != 0 ||
        pread(fd, &attempts, sizeof(attempts), 0) !=
            (ssize_t)sizeof(attempts)) {
        goto cleanup;
    }
    if (attempts[index] >= UINT32_C(5)) {
        result = 0;
        goto cleanup;
    }
    attempts[index]++;
    if (pwrite(fd, &attempts, sizeof(attempts), 0) !=
            (ssize_t)sizeof(attempts) ||
        fsync(fd) != 0) {
        goto cleanup;
    }
    result = 1;

cleanup:
    if (fd >= 0) {
        if (flock(fd, LOCK_UN) != 0 || close(fd) != 0) {
            result = -1;
        }
    }
    return result;
}

static int reset_attempts(uid_t uid)
{
    uint32_t attempts[INTEGRATION_SCOPE_COUNT];
    size_t index;
    int fd = open_state();
    int result = -1;

    if (scope_index(uid, &index) == 0 && fd >= 0 &&
        flock(fd, LOCK_EX) == 0 &&
        pread(fd, &attempts, sizeof(attempts), 0) ==
            (ssize_t)sizeof(attempts) &&
        (attempts[index] = UINT32_C(0),
         pwrite(fd, &attempts, sizeof(attempts), 0)) ==
            (ssize_t)sizeof(attempts) &&
        fsync(fd) == 0) {
        result = 0;
    }
    if (fd >= 0) {
        if (flock(fd, LOCK_UN) != 0 || close(fd) != 0) {
            result = -1;
        }
    }
    return result;
}

int ocra_integration_getpwnam_r(const char *name, struct passwd *entry,
                                char *buffer, size_t buffer_length,
                                struct passwd **result)
{
    static const char expected_name[] = "isolated-user";
    static const char second_name[] = "isolated-user-two";
    uid_t uid;

    if (strcmp(name, expected_name) == 0) {
        uid = INTEGRATION_UID;
    } else if (strcmp(name, second_name) == 0) {
        uid = INTEGRATION_SECOND_UID;
    } else {
        *result = NULL;
        return 0;
    }
    if (buffer_length < strlen(name) + 1U) {
        *result = NULL;
        return 0;
    }
    (void)memcpy(buffer, name, strlen(name) + 1U);
    (void)memset(entry, 0, sizeof(*entry));
    entry->pw_name = buffer;
    entry->pw_uid = uid;
    *result = entry;
    return 0;
}

int ocra_secret_store_load(uid_t uid, const char *service,
                           struct ocra_secret_record *record)
{
    static const unsigned char secret[] =
        "12345678901234567890123456789012";

    if ((uid != INTEGRATION_UID && uid != INTEGRATION_SECOND_UID) ||
        service == NULL ||
        strcmp(service, "ocra-integration") != 0 || record == NULL) {
        return -1;
    }
    (void)memcpy(record->secret, secret, OCRA_SECRET_BYTES);
    (void)memcpy(record->key_id, "0011223344556677",
                 OCRA_KEY_ID_HEX_LENGTH + 1U);
    return 0;
}

void ocra_secret_record_clear(struct ocra_secret_record *record)
{
    if (record != NULL) {
        secure_memory_clear(record, sizeof(*record));
    }
}

int ocra_rate_limit_reserve(uid_t uid, const char *service,
                            const char *key_id,
                            char challenge[OCRA_CHALLENGE_DIGITS + 1U])
{
    int reservation;

    if ((uid != INTEGRATION_UID && uid != INTEGRATION_SECOND_UID) ||
        service == NULL || key_id == NULL || challenge == NULL ||
        strcmp(service, "ocra-integration") != 0 ||
        strcmp(key_id, "0011223344556677") != 0) {
        return -1;
    }
    reservation = reserve_attempt(uid);
    if (reservation != 1) {
        return -1;
    }
    (void)memcpy(challenge, "1234567890", OCRA_CHALLENGE_DIGITS + 1U);
    return 0;
}

int ocra_rate_limit_reset(uid_t uid, const char *service, const char *key_id)
{
    if ((uid != INTEGRATION_UID && uid != INTEGRATION_SECOND_UID) ||
        service == NULL || key_id == NULL ||
        strcmp(service, "ocra-integration") != 0 ||
        strcmp(key_id, "0011223344556677") != 0) {
        return -1;
    }
    return reset_attempts(uid);
}
