#define _GNU_SOURCE

#include "secret_file.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PTD_READ_BUFFER_SIZE (PTD_MAX_SECRET_LEN + 3U)

static void secure_memzero(void *value, size_t length)
{
    if (value == NULL) return;
    volatile unsigned char *bytes = (volatile unsigned char *)value;
    while (length > 0U) {
        *bytes++ = 0U;
        length--;
    }
}

static int validate_private_directory(int fd, uid_t expected_owner)
{
    struct stat status;
    if (fstat(fd, &status) != 0) return -1;
    return S_ISDIR(status.st_mode) && status.st_uid == expected_owner &&
                   (status.st_mode & (mode_t)0077) == 0
               ? 0
               : -1;
}

static int validate_private_file(int fd, uid_t expected_owner)
{
    struct stat status;
    if (fstat(fd, &status) != 0) return -1;
    if (!S_ISREG(status.st_mode) || status.st_uid != expected_owner ||
        (status.st_mode & (mode_t)0077) != 0 || status.st_nlink != 1 ||
        status.st_size <= (off_t)0 ||
        status.st_size > (off_t)(PTD_MAX_SECRET_LEN + 2U)) return -1;
    return 0;
}

static int read_bounded(int fd, char buffer[PTD_READ_BUFFER_SIZE],
                        size_t *length_out)
{
    size_t total = 0U;
    while (total < PTD_READ_BUFFER_SIZE) {
        ssize_t count = read(fd, buffer + total, PTD_READ_BUFFER_SIZE - total);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (count == 0) break;
        total += (size_t)count;
    }
    if (total == 0U || total == PTD_READ_BUFFER_SIZE) return -1;
    *length_out = total;
    return 0;
}

int ptd_read_secret_at(int home_fd, uid_t expected_owner,
                       const struct ptd_domain *domain, char *secret_out,
                       size_t secret_out_size)
{
    char buffer[PTD_READ_BUFFER_SIZE];
    size_t length = 0U;
    int directory_fd = -1;
    int secret_fd = -1;
    int result = PTD_SECRET_ERROR;

    memset(buffer, 0, sizeof(buffer));
    if (home_fd < 0 || domain == NULL || domain->service == NULL ||
        domain->secret_file == NULL ||
        ptd_domain_for_service(domain->service) != domain ||
        secret_out == NULL || secret_out_size < PTD_MAX_SECRET_LEN + 1U) {
        goto cleanup;
    }
    memset(secret_out, 0, secret_out_size);

    directory_fd = openat(home_fd, PTD_SECRET_DIRECTORY,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0) {
        result = errno == ENOENT ? PTD_SECRET_NOT_FOUND : PTD_SECRET_ERROR;
        goto cleanup;
    }
    if (validate_private_directory(directory_fd, expected_owner) != 0) goto cleanup;

    secret_fd = openat(directory_fd, domain->secret_file,
                       O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (secret_fd < 0) {
        result = errno == ENOENT ? PTD_SECRET_NOT_FOUND : PTD_SECRET_ERROR;
        goto cleanup;
    }
    if (validate_private_file(secret_fd, expected_owner) != 0 ||
        read_bounded(secret_fd, buffer, &length) != 0) goto cleanup;

    if (length > 0U && buffer[length - 1U] == '\n') {
        length--;
        if (length > 0U && buffer[length - 1U] == '\r') length--;
    }
    if (ptd_validate_base32_secret(buffer, length) != 0) goto cleanup;

    memcpy(secret_out, buffer, length);
    secret_out[length] = '\0';
    result = PTD_SECRET_OK;

cleanup:
    if (secret_fd >= 0) close(secret_fd);
    if (directory_fd >= 0) close(directory_fd);
    secure_memzero(buffer, sizeof(buffer));
    if (result != PTD_SECRET_OK && secret_out != NULL && secret_out_size > 0U)
        secure_memzero(secret_out, secret_out_size);
    return result;
}
