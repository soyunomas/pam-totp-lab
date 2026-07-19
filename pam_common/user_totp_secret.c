#define _GNU_SOURCE

#include "user_totp_secret.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define READ_CAPACITY (USER_TOTP_SECRET_MAX_LENGTH + 3U)
#define PASSWD_BUFFER_LIMIT (1U << 20)

void user_totp_secure_memzero(void *buffer, size_t length)
{
    volatile unsigned char *cursor = (volatile unsigned char *)buffer;

    if (buffer == NULL) return;
    while (length > 0U) {
        *cursor++ = 0U;
        length--;
    }
    __asm__ __volatile__("" : : "r"(buffer) : "memory");
}

int user_totp_validate_base32(const char *secret, size_t length)
{
    if (secret == NULL || length < USER_TOTP_SECRET_MIN_LENGTH ||
        length > USER_TOTP_SECRET_MAX_LENGTH) {
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

static int validate_directory(int fd, uid_t expected_owner)
{
    struct stat status;

    return fstat(fd, &status) == 0 && S_ISDIR(status.st_mode) &&
                   status.st_uid == expected_owner &&
                   (status.st_mode & (mode_t)0022) == 0
               ? 0
               : -1;
}

static int validate_secret_file(int fd, uid_t expected_owner)
{
    struct stat status;

    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_uid != expected_owner ||
        (status.st_mode & (mode_t)0077) != 0 || status.st_nlink != 1 ||
        status.st_size < (off_t)USER_TOTP_SECRET_MIN_LENGTH ||
        status.st_size > (off_t)(USER_TOTP_SECRET_MAX_LENGTH + 2U)) {
        return -1;
    }
    return 0;
}

int user_totp_secret_read_at(int directory_fd, const char *filename,
                             uid_t expected_owner, char *secret_out,
                             size_t secret_capacity)
{
    char raw[READ_CAPACITY];
    size_t total = 0U;
    int secret_fd = -1;
    int result = USER_TOTP_SECRET_ERROR;

    if (directory_fd < 0 || validate_directory(directory_fd, expected_owner) != 0 ||
        filename == NULL || filename[0] == '\0' ||
        strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0 ||
        strchr(filename, '/') != NULL || secret_out == NULL ||
        secret_capacity <= USER_TOTP_SECRET_MAX_LENGTH) {
        return USER_TOTP_SECRET_ERROR;
    }
    memset(raw, 0, sizeof(raw));
    memset(secret_out, 0, secret_capacity);

    secret_fd = openat(directory_fd, filename,
                       O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (secret_fd < 0) {
        return errno == ENOENT ? USER_TOTP_SECRET_NOT_FOUND
                               : USER_TOTP_SECRET_ERROR;
    }
    if (validate_secret_file(secret_fd, expected_owner) != 0) goto cleanup;

    while (total < sizeof(raw)) {
        ssize_t count = read(secret_fd, raw + total, sizeof(raw) - total);
        if (count < 0) {
            if (errno == EINTR) continue;
            goto cleanup;
        }
        if (count == 0) break;
        total += (size_t)count;
    }
    if (total == sizeof(raw)) goto cleanup;
    if (total > 0U && raw[total - 1U] == '\n') total--;
    if (total > 0U && raw[total - 1U] == '\r') total--;
    if (memchr(raw, '\n', total) != NULL ||
        memchr(raw, '\r', total) != NULL ||
        memchr(raw, '\0', total) != NULL ||
        user_totp_validate_base32(raw, total) != 0) {
        goto cleanup;
    }

    memcpy(secret_out, raw, total);
    secret_out[total] = '\0';
    result = USER_TOTP_SECRET_OK;

cleanup:
    close(secret_fd);
    user_totp_secure_memzero(raw, sizeof(raw));
    if (result != USER_TOTP_SECRET_OK) {
        user_totp_secure_memzero(secret_out, secret_capacity);
    }
    return result;
}

int user_totp_secret_get(const char *username, const char *filename,
                         char *secret_out, size_t secret_capacity,
                         uid_t *uid_out)
{
    long configured_size;
    size_t passwd_buffer_size;
    char *passwd_buffer = NULL;
    struct passwd pwd;
    struct passwd *pwd_result = NULL;
    int home_fd = -1;
    int result = USER_TOTP_SECRET_ERROR;

    if (username == NULL || filename == NULL || secret_out == NULL ||
        secret_capacity <= USER_TOTP_SECRET_MAX_LENGTH || uid_out == NULL) {
        return USER_TOTP_SECRET_ERROR;
    }
    user_totp_secure_memzero(secret_out, secret_capacity);
    configured_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    passwd_buffer_size = configured_size > 0 ? (size_t)configured_size : 16384U;
    if (passwd_buffer_size > PASSWD_BUFFER_LIMIT) return USER_TOTP_SECRET_ERROR;

    passwd_buffer = calloc(1U, passwd_buffer_size);
    if (passwd_buffer == NULL) return USER_TOTP_SECRET_ERROR;
    memset(&pwd, 0, sizeof(pwd));
    if (getpwnam_r(username, &pwd, passwd_buffer, passwd_buffer_size,
                   &pwd_result) != 0 ||
        pwd_result == NULL || pwd.pw_dir == NULL || pwd.pw_dir[0] != '/') {
        goto cleanup;
    }
    *uid_out = pwd.pw_uid;

    home_fd = open(pwd.pw_dir,
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (home_fd < 0 || validate_directory(home_fd, pwd.pw_uid) != 0) {
        goto cleanup;
    }
    result = user_totp_secret_read_at(home_fd, filename, pwd.pw_uid,
                                      secret_out, secret_capacity);

cleanup:
    if (home_fd >= 0) close(home_fd);
    user_totp_secure_memzero(passwd_buffer, passwd_buffer_size);
    free(passwd_buffer);
    if (result != USER_TOTP_SECRET_OK &&
        result != USER_TOTP_SECRET_NOT_FOUND) {
        user_totp_secure_memzero(secret_out, secret_capacity);
    }
    return result;
}
