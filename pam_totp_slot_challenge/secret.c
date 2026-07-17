#define _GNU_SOURCE

#include "secret.h"
#include "slot_policy.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PTSC_READ_BUFFER_SIZE (PTSC_MAX_SECRET_LEN + 2U)

void ptsc_secure_memzero(void *buffer, size_t length)
{
    volatile unsigned char *cursor = (volatile unsigned char *)buffer;

    if (buffer == NULL) {
        return;
    }
    while (length > 0U) {
        *cursor++ = 0U;
        length--;
    }
}

int ptsc_validate_base32_secret(const char *secret, size_t length)
{
    if (secret == NULL || length < PTSC_MIN_SECRET_LEN ||
        length > PTSC_MAX_SECRET_LEN) {
        return -1;
    }

    for (size_t i = 0U; i < length; i++) {
        unsigned char ch = (unsigned char)secret[i];

        if (!((ch >= (unsigned char)'A' && ch <= (unsigned char)'Z') ||
              (ch >= (unsigned char)'2' && ch <= (unsigned char)'7'))) {
            return -1;
        }
    }
    return 0;
}

static int validate_directory_fd(int fd, uid_t expected_owner,
                                 mode_t forbidden_permissions)
{
    struct stat st;

    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != expected_owner ||
        (st.st_mode & forbidden_permissions) != 0) {
        return -1;
    }
    return 0;
}

static int validate_secret_fd(int fd, uid_t expected_owner)
{
    struct stat st;

    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != expected_owner || (st.st_mode & (mode_t)0077) != 0 ||
        st.st_nlink != 1 || st.st_size < (off_t)PTSC_MIN_SECRET_LEN ||
        st.st_size > (off_t)(PTSC_MAX_SECRET_LEN + 1U)) {
        return -1;
    }
    return 0;
}

static int read_bounded_secret(int fd, char *secret_out, size_t secret_capacity)
{
    char buffer[PTSC_READ_BUFFER_SIZE];
    size_t total = 0U;
    int result = PTSC_SECRET_ERROR;

    if (secret_out == NULL || secret_capacity <= PTSC_MAX_SECRET_LEN) {
        return PTSC_SECRET_ERROR;
    }

    while (total < sizeof(buffer)) {
        ssize_t count = read(fd, buffer + total, sizeof(buffer) - total);

        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            goto cleanup;
        }
        if (count == 0) {
            break;
        }
        total += (size_t)count;
    }

    if (total == sizeof(buffer)) {
        unsigned char extra;
        ssize_t count;

        do {
            count = read(fd, &extra, 1U);
        } while (count < 0 && errno == EINTR);
        if (count != 0) {
            goto cleanup;
        }
    }

    if (total > 0U && buffer[total - 1U] == '\n') {
        total--;
    }
    if (ptsc_validate_base32_secret(buffer, total) != 0 ||
        memchr(buffer, '\n', total) != NULL ||
        memchr(buffer, '\0', total) != NULL) {
        goto cleanup;
    }

    memcpy(secret_out, buffer, total);
    secret_out[total] = '\0';
    result = PTSC_SECRET_OK;

cleanup:
    ptsc_secure_memzero(buffer, sizeof(buffer));
    if (result != PTSC_SECRET_OK) {
        ptsc_secure_memzero(secret_out, secret_capacity);
    }
    return result;
}

int ptsc_read_slot_secret(const char *home_directory, uid_t expected_owner,
                          size_t slot_index, char *secret_out,
                          size_t secret_capacity)
{
    const struct ptsc_slot *slot;
    int home_fd = -1;
    int secret_dir_fd = -1;
    int secret_fd = -1;
    int result = PTSC_SECRET_ERROR;

    if (home_directory == NULL || secret_out == NULL ||
        secret_capacity <= PTSC_MAX_SECRET_LEN) {
        return PTSC_SECRET_ERROR;
    }
    ptsc_secure_memzero(secret_out, secret_capacity);

    slot = ptsc_slot_by_index(slot_index);
    if (slot == NULL) {
        return PTSC_SECRET_ERROR;
    }

    home_fd = open(home_directory,
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (home_fd < 0 ||
        validate_directory_fd(home_fd, expected_owner, (mode_t)0022) != 0) {
        goto cleanup;
    }

    secret_dir_fd = openat(home_fd, PTSC_SECRET_DIRECTORY,
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (secret_dir_fd < 0) {
        if (errno == ENOENT) {
            result = PTSC_SECRET_NOT_FOUND;
        }
        goto cleanup;
    }
    if (validate_directory_fd(secret_dir_fd, expected_owner,
                              (mode_t)0077) != 0) {
        goto cleanup;
    }

    secret_fd = openat(secret_dir_fd, slot->secret_file,
                       O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (secret_fd < 0) {
        if (errno == ENOENT) {
            result = PTSC_SECRET_NOT_FOUND;
        }
        goto cleanup;
    }
    if (validate_secret_fd(secret_fd, expected_owner) != 0) {
        goto cleanup;
    }

    result = read_bounded_secret(secret_fd, secret_out, secret_capacity);

cleanup:
    if (secret_fd >= 0) {
        close(secret_fd);
    }
    if (secret_dir_fd >= 0) {
        close(secret_dir_fd);
    }
    if (home_fd >= 0) {
        close(home_fd);
    }
    if (result != PTSC_SECRET_OK) {
        ptsc_secure_memzero(secret_out, secret_capacity);
    }
    return result;
}
