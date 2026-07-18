#define _GNU_SOURCE

#include "secure_store.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int validate_directory_fd(int fd, uid_t owner, mode_t forbidden)
{
    struct stat st;

    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != owner ||
        (st.st_mode & forbidden) != 0) {
        return -1;
    }
    return 0;
}

static int validate_regular_fd(int fd, uid_t owner, mode_t exact_mode)
{
    struct stat st;

    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != owner ||
        st.st_nlink != 1 || (st.st_mode & (mode_t)0777) != exact_mode) {
        return -1;
    }
    return 0;
}

static int read_regular_file(int fd, size_t maximum, char **buffer_out,
                             size_t *length_out)
{
    struct stat st;
    char *buffer = NULL;
    size_t total = 0U;

    if (buffer_out == NULL || length_out == NULL || maximum == 0U ||
        fstat(fd, &st) != 0 || st.st_size <= (off_t)0 ||
        (uintmax_t)st.st_size > (uintmax_t)maximum) {
        return -1;
    }

    buffer = calloc(1U, (size_t)st.st_size + 1U);
    if (buffer == NULL) return -1;

    while (total < (size_t)st.st_size) {
        ssize_t count = pread(fd, buffer + total, (size_t)st.st_size - total,
                              (off_t)total);
        if (count < 0) {
            if (errno == EINTR) continue;
            goto error;
        }
        if (count == 0) goto error;
        total += (size_t)count;
    }

    *buffer_out = buffer;
    *length_out = total;
    return 0;

error:
    pso_secure_memzero(buffer, (size_t)st.st_size + 1U);
    free(buffer);
    return -1;
}

int pso_validate_base32_secret(const char *secret, size_t length)
{
    if (secret == NULL || length < PSO_MIN_SECRET_LEN ||
        length > PSO_MAX_SECRET_LEN) {
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

int pso_read_config_at(int security_dir_fd, uid_t expected_owner,
                       struct pso_config *config_out)
{
    int fd = -1;
    char *buffer = NULL;
    size_t length = 0U;
    int result = PSO_STORE_ERROR;

    if (config_out == NULL ||
        validate_directory_fd(security_dir_fd, expected_owner,
                              (mode_t)0022) != 0) {
        return PSO_STORE_ERROR;
    }

    fd = openat(security_dir_fd, PSO_CONFIG_FILE,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? PSO_STORE_NOT_FOUND : PSO_STORE_ERROR;
    if (validate_regular_fd(fd, expected_owner, (mode_t)0600) != 0 ||
        read_regular_file(fd, PSO_MAX_CONFIG_SIZE, &buffer, &length) != 0 ||
        pso_parse_config(buffer, length, config_out) != 0) {
        goto cleanup;
    }
    result = PSO_STORE_OK;

cleanup:
    if (buffer != NULL) {
        pso_secure_memzero(buffer, length + 1U);
        free(buffer);
    }
    close(fd);
    return result;
}

int pso_read_secret_at(int security_dir_fd, uid_t expected_owner,
                       const char *secret_name, char *secret_out,
                       size_t secret_capacity)
{
    int directory_fd = -1;
    int secret_fd = -1;
    char *buffer = NULL;
    size_t length = 0U;
    size_t secret_length;
    int result = PSO_STORE_ERROR;

    if (secret_out == NULL || secret_capacity < PSO_MIN_SECRET_LEN + 1U ||
        pso_validate_secret_name(secret_name) != 0 ||
        validate_directory_fd(security_dir_fd, expected_owner,
                              (mode_t)0022) != 0) {
        return PSO_STORE_ERROR;
    }
    memset(secret_out, 0, secret_capacity);

    directory_fd = openat(security_dir_fd, PSO_SECRET_DIRECTORY,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0) {
        return errno == ENOENT ? PSO_STORE_NOT_FOUND : PSO_STORE_ERROR;
    }
    if (validate_directory_fd(directory_fd, expected_owner, (mode_t)0077) != 0) {
        goto cleanup;
    }

    secret_fd = openat(directory_fd, secret_name,
                       O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (secret_fd < 0) {
        result = errno == ENOENT ? PSO_STORE_NOT_FOUND : PSO_STORE_ERROR;
        goto cleanup;
    }
    if (validate_regular_fd(secret_fd, expected_owner, (mode_t)0600) != 0 ||
        read_regular_file(secret_fd, PSO_MAX_SECRET_LEN + 2U, &buffer,
                          &length) != 0 ||
        memchr(buffer, '\0', length) != NULL) {
        goto cleanup;
    }

    secret_length = length;
    if (secret_length > 0U && buffer[secret_length - 1U] == '\n') {
        secret_length--;
    }
    if (secret_length > 0U && buffer[secret_length - 1U] == '\r') {
        secret_length--;
    }
    if (secret_length == 0U || secret_length + 1U > secret_capacity ||
        memchr(buffer, '\n', secret_length) != NULL ||
        memchr(buffer, '\r', secret_length) != NULL ||
        pso_validate_base32_secret(buffer, secret_length) != 0) {
        goto cleanup;
    }

    memcpy(secret_out, buffer, secret_length);
    secret_out[secret_length] = '\0';
    result = PSO_STORE_OK;

cleanup:
    if (buffer != NULL) {
        pso_secure_memzero(buffer, length + 1U);
        free(buffer);
    }
    if (secret_fd >= 0) close(secret_fd);
    if (directory_fd >= 0) close(directory_fd);
    if (result != PSO_STORE_OK) pso_secure_memzero(secret_out, secret_capacity);
    return result;
}

static int open_security_directory(void)
{
    int fd;

    if (geteuid() != (uid_t)0) return -1;
    fd = open(PSO_SECURITY_DIRECTORY,
              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || validate_directory_fd(fd, (uid_t)0, (mode_t)0022) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

int pso_load_config(struct pso_config *config_out)
{
    int fd = open_security_directory();
    int result;

    if (fd < 0) return PSO_STORE_ERROR;
    result = pso_read_config_at(fd, (uid_t)0, config_out);
    close(fd);
    return result;
}

int pso_load_secret(const char *secret_name, char *secret_out,
                    size_t secret_capacity)
{
    int fd = open_security_directory();
    int result;

    if (fd < 0) return PSO_STORE_ERROR;
    result = pso_read_secret_at(fd, (uid_t)0, secret_name, secret_out,
                                secret_capacity);
    close(fd);
    return result;
}
