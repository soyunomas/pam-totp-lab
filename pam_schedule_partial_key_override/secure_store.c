#define _GNU_SOURCE

#include "secure_store.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SECURITY_DIRECTORY "/etc/security"

static int valid_directory(int fd, mode_t forbidden)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) &&
                   st.st_uid == (uid_t)0 && (st.st_mode & forbidden) == 0
               ? 0
               : -1;
}

static int valid_file(int fd)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
                   st.st_uid == (uid_t)0 && st.st_nlink == 1 &&
                   (st.st_mode & (mode_t)0777) == (mode_t)0600
               ? 0
               : -1;
}

static int read_file(int fd, size_t maximum, unsigned char **out,
                     size_t *length_out)
{
    struct stat st;
    unsigned char *buffer = NULL;
    size_t total = 0U;

    if (out == NULL || length_out == NULL || fstat(fd, &st) != 0 ||
        st.st_size <= (off_t)0 || (uintmax_t)st.st_size > maximum) {
        return -1;
    }
    buffer = calloc(1U, (size_t)st.st_size + 1U);
    if (buffer == NULL) return -1;
    while (total < (size_t)st.st_size) {
        ssize_t count = pread(fd, buffer + total,
                              (size_t)st.st_size - total, (off_t)total);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) goto fail;
        total += (size_t)count;
    }
    *out = buffer;
    *length_out = total;
    return 0;

fail:
    pso_secure_memzero(buffer, (size_t)st.st_size + 1U);
    free(buffer);
    return -1;
}

static int open_security(void)
{
    int fd;
    if (geteuid() != (uid_t)0) return -1;
    fd = open(SECURITY_DIRECTORY,
              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || valid_directory(fd, (mode_t)0022) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

int spk_load_config(struct pso_config *config_out)
{
    unsigned char *buffer = NULL;
    size_t length = 0U;
    int security_fd = -1;
    int fd = -1;
    int result = SPK_STORE_ERROR;

    if (config_out == NULL) return SPK_STORE_ERROR;
    security_fd = open_security();
    if (security_fd < 0) return SPK_STORE_ERROR;
    fd = openat(security_fd, SPK_CONFIG_FILE,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd >= 0 && valid_file(fd) == 0 &&
        read_file(fd, PSO_MAX_CONFIG_SIZE, &buffer, &length) == 0 &&
        pso_parse_authorizer_config((const char *)buffer, length,
                                    config_out) == 0) {
        result = SPK_STORE_OK;
    }
    if (buffer != NULL) {
        pso_secure_memzero(buffer, length + 1U);
        free(buffer);
    }
    if (fd >= 0) close(fd);
    close(security_fd);
    return result;
}

int spk_load_key(const char *authorizer, struct pk_key_data *key_out,
                 unsigned char key_id[32])
{
    char name[64];
    unsigned char *buffer = NULL;
    size_t length = 0U;
    unsigned int digest_length = 0U;
    int security_fd = -1;
    int directory_fd = -1;
    int fd = -1;
    int written;
    int result = SPK_STORE_ERROR;

    if (key_out == NULL || key_id == NULL ||
        pso_validate_authorizer_name(authorizer) != 0) {
        return SPK_STORE_ERROR;
    }
    pk_key_data_clear(key_out);
    memset(key_id, 0, 32U);
    written = snprintf(name, sizeof(name), "%s.pkey", authorizer);
    if (written < 0 || (size_t)written >= sizeof(name)) return SPK_STORE_ERROR;

    security_fd = open_security();
    if (security_fd < 0) return SPK_STORE_ERROR;
    directory_fd = openat(security_fd, SPK_KEY_DIRECTORY,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0 || valid_directory(directory_fd, (mode_t)0077) != 0) {
        goto cleanup;
    }
    fd = openat(directory_fd, name,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || valid_file(fd) != 0 ||
        read_file(fd, PK_MAX_FILE_SIZE, &buffer, &length) != 0 ||
        pk_parse_key_data(buffer, length, key_out) != 0 ||
        EVP_Digest(buffer, length, key_id, &digest_length, EVP_sha256(),
                   NULL) != 1 || digest_length != 32U) {
        goto cleanup;
    }
    result = SPK_STORE_OK;

cleanup:
    if (buffer != NULL) {
        pso_secure_memzero(buffer, length + 1U);
        free(buffer);
    }
    if (fd >= 0) close(fd);
    if (directory_fd >= 0) close(directory_fd);
    close(security_fd);
    if (result != SPK_STORE_OK) {
        pk_key_data_clear(key_out);
        pso_secure_memzero(key_id, 32U);
    }
    return result;
}
