#define _GNU_SOURCE

#include "secret.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void pts_secure_memzero(void *buffer, size_t length)
{
    volatile unsigned char *cursor = (volatile unsigned char *)buffer;
    if (buffer == NULL) return;
    while (length-- > 0U) *cursor++ = 0U;
    __asm__ __volatile__("" : : "r"(buffer) : "memory");
}

int pts_validate_base32_secret(const char *secret, size_t length)
{
    if (secret == NULL || length < PTS_MIN_SECRET_LENGTH ||
        length > PTS_MAX_SECRET_LENGTH) {
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

static int pts_validate_secret_file(int fd, uid_t expected_owner)
{
    struct stat st;

    if (fstat(fd, &st) != 0) return -1;
    if (!S_ISREG(st.st_mode) || st.st_uid != expected_owner ||
        (st.st_mode & (mode_t)0077) != 0 || st.st_nlink != 1 ||
        st.st_size < (off_t)PTS_MIN_SECRET_LENGTH ||
        st.st_size > (off_t)(PTS_MAX_SECRET_LENGTH + 2U)) {
        return -1;
    }
    return 0;
}

int pts_read_secret_at(int directory_fd, const char *name, uid_t expected_owner,
                       char *secret_out, size_t secret_out_size)
{
    char raw[PTS_MAX_SECRET_LENGTH + 3U];
    size_t total = 0U;
    int fd = -1;
    int result = PTS_SECRET_ERROR;

    if (directory_fd < 0 || name == NULL || secret_out == NULL ||
        secret_out_size < PTS_MAX_SECRET_LENGTH + 1U || name[0] == '\0' ||
        strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
        strchr(name, '/') != NULL) {
        return PTS_SECRET_ERROR;
    }
    memset(raw, 0, sizeof(raw));
    memset(secret_out, 0, secret_out_size);

    fd = openat(directory_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        return errno == ENOENT ? PTS_SECRET_NOT_FOUND : PTS_SECRET_ERROR;
    }
    if (pts_validate_secret_file(fd, expected_owner) != 0) goto cleanup;

    while (total < sizeof(raw)) {
        ssize_t count = read(fd, raw + total, sizeof(raw) - total);
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
    if (memchr(raw, '\n', total) != NULL || memchr(raw, '\r', total) != NULL ||
        pts_validate_base32_secret(raw, total) != 0) {
        goto cleanup;
    }

    memcpy(secret_out, raw, total);
    secret_out[total] = '\0';
    result = PTS_SECRET_OK;

cleanup:
    if (fd >= 0) close(fd);
    pts_secure_memzero(raw, sizeof(raw));
    if (result != PTS_SECRET_OK) pts_secure_memzero(secret_out, secret_out_size);
    return result;
}

static int pts_restore_credentials(uid_t old_uid, gid_t old_gid,
                                   int group_count, const gid_t *groups)
{
    int failed = 0;

    if (seteuid(old_uid) != 0) failed = 1;
    if (setegid(old_gid) != 0) failed = 1;
    if (group_count > 0 && groups != NULL) {
        if (setgroups((size_t)group_count, groups) != 0) failed = 1;
    } else if (setgroups(0U, NULL) != 0) {
        failed = 1;
    }
    return failed ? -1 : 0;
}

int pts_get_user_secret(const char *username, char *secret_out,
                        size_t secret_out_size, uid_t *uid_out)
{
    long configured_size;
    size_t passwd_buffer_size;
    char *passwd_buffer = NULL;
    struct passwd pwd;
    struct passwd *pwd_result = NULL;
    uid_t old_uid;
    gid_t old_gid;
    int group_count;
    gid_t *groups = NULL;
    int home_fd = -1;
    int result = PTS_SECRET_ERROR;

    if (username == NULL || secret_out == NULL || uid_out == NULL) return PTS_SECRET_ERROR;
    configured_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    passwd_buffer_size = configured_size > 0 ? (size_t)configured_size : 16384U;
    if (passwd_buffer_size > (1U << 20)) return PTS_SECRET_ERROR;

    passwd_buffer = calloc(1U, passwd_buffer_size);
    if (passwd_buffer == NULL) return PTS_SECRET_ERROR;
    memset(&pwd, 0, sizeof(pwd));
    if (getpwnam_r(username, &pwd, passwd_buffer, passwd_buffer_size, &pwd_result) != 0 ||
        pwd_result == NULL || pwd.pw_dir == NULL || pwd.pw_dir[0] != '/') {
        goto cleanup;
    }
    *uid_out = pwd.pw_uid;

    old_uid = geteuid();
    old_gid = getegid();
    group_count = getgroups(0, NULL);
    if (group_count < 0) goto cleanup;
    if (group_count > 0) {
        groups = calloc((size_t)group_count, sizeof(*groups));
        if (groups == NULL || getgroups(group_count, groups) != group_count) goto cleanup;
    }

    if (initgroups(username, pwd.pw_gid) != 0 || setegid(pwd.pw_gid) != 0 ||
        seteuid(pwd.pw_uid) != 0) {
        if (pts_restore_credentials(old_uid, old_gid, group_count, groups) != 0) abort();
        goto cleanup;
    }

    home_fd = open(pwd.pw_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (home_fd >= 0) {
        struct stat home_stat;
        if (fstat(home_fd, &home_stat) == 0 && S_ISDIR(home_stat.st_mode) &&
            home_stat.st_uid == pwd.pw_uid && (home_stat.st_mode & (mode_t)0022) == 0) {
            result = pts_read_secret_at(home_fd, PTS_SECRET_FILE, pwd.pw_uid,
                                        secret_out, secret_out_size);
        }
    }

    if (pts_restore_credentials(old_uid, old_gid, group_count, groups) != 0) abort();

cleanup:
    if (home_fd >= 0) close(home_fd);
    if (groups != NULL) {
        pts_secure_memzero(groups, (size_t)group_count * sizeof(*groups));
        free(groups);
    }
    if (passwd_buffer != NULL) {
        pts_secure_memzero(passwd_buffer, passwd_buffer_size);
        free(passwd_buffer);
    }
    if (result != PTS_SECRET_OK && result != PTS_SECRET_NOT_FOUND) {
        pts_secure_memzero(secret_out, secret_out_size);
    }
    return result;
}
