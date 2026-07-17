#define _GNU_SOURCE

#include "../secret.h"

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char valid_secret[] = "JBSWY3DPEHPK3PXP";

static void write_file(const char *path, const char *content, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    size_t length = strlen(content);

    assert(fd >= 0);
    assert(write(fd, content, length) == (ssize_t)length);
    assert(close(fd) == 0);
    assert(chmod(path, mode) == 0);
}

static void reset_layout(const char *home, char *dir_path, char *file_path)
{
    char command[PATH_MAX + 32U];
    int written = snprintf(command, sizeof(command), "rm -rf -- '%s/%s'", home,
                           PTSC_SECRET_DIRECTORY);

    assert(written > 0 && (size_t)written < sizeof(command));
    assert(system(command) == 0);
    assert(snprintf(dir_path, PATH_MAX, "%s/%s", home,
                    PTSC_SECRET_DIRECTORY) > 0);
    assert(mkdir(dir_path, 0700) == 0);
    assert(snprintf(file_path, PATH_MAX, "%s/A.secret", dir_path) > 0);
    write_file(file_path, valid_secret, 0600);
}

int main(void)
{
    char template[] = "/tmp/ptsc-secret-XXXXXX";
    char *home = mkdtemp(template);
    char dir_path[PATH_MAX];
    char file_path[PATH_MAX];
    char other_path[PATH_MAX];
    char secret[PTSC_MAX_SECRET_LEN + 1U];
    uid_t uid = getuid();

    assert(home != NULL);
    assert(chmod(home, 0700) == 0);

    reset_layout(home, dir_path, file_path);
    assert(ptsc_read_slot_secret(home, uid, 0U, secret, sizeof(secret)) ==
           PTSC_SECRET_OK);
    assert(strcmp(secret, valid_secret) == 0);

    reset_layout(home, dir_path, file_path);
    assert(chmod(file_path, 0644) == 0);
    assert(ptsc_read_slot_secret(home, uid, 0U, secret, sizeof(secret)) ==
           PTSC_SECRET_ERROR);

    reset_layout(home, dir_path, file_path);
    assert(chmod(dir_path, 0755) == 0);
    assert(ptsc_read_slot_secret(home, uid, 0U, secret, sizeof(secret)) ==
           PTSC_SECRET_ERROR);

    reset_layout(home, dir_path, file_path);
    assert(unlink(file_path) == 0);
    assert(symlink("/etc/passwd", file_path) == 0);
    assert(ptsc_read_slot_secret(home, uid, 0U, secret, sizeof(secret)) ==
           PTSC_SECRET_ERROR);

    reset_layout(home, dir_path, file_path);
    assert(snprintf(other_path, sizeof(other_path), "%s/copy.secret", dir_path) > 0);
    assert(link(file_path, other_path) == 0);
    assert(ptsc_read_slot_secret(home, uid, 0U, secret, sizeof(secret)) ==
           PTSC_SECRET_ERROR);

    reset_layout(home, dir_path, file_path);
    write_file(file_path, "jbswy3dpehpk3pxp", 0600);
    assert(ptsc_read_slot_secret(home, uid, 0U, secret, sizeof(secret)) ==
           PTSC_SECRET_ERROR);

    reset_layout(home, dir_path, file_path);
    write_file(file_path, "JBSWY3DPEHPK3PXP=", 0600);
    assert(ptsc_read_slot_secret(home, uid, 0U, secret, sizeof(secret)) ==
           PTSC_SECRET_ERROR);

    reset_layout(home, dir_path, file_path);
    write_file(file_path, "JBSWY3DPEHPK3PXP\nSECONDLINE", 0600);
    assert(ptsc_read_slot_secret(home, uid, 0U, secret, sizeof(secret)) ==
           PTSC_SECRET_ERROR);

    reset_layout(home, dir_path, file_path);
    assert(ptsc_read_slot_secret(home, uid, 4U, secret, sizeof(secret)) ==
           PTSC_SECRET_ERROR);

    reset_layout(home, dir_path, file_path);
    assert(unlink(file_path) == 0);
    assert(ptsc_read_slot_secret(home, uid, 0U, secret, sizeof(secret)) ==
           PTSC_SECRET_NOT_FOUND);

    assert(snprintf(other_path, sizeof(other_path), "rm -rf -- '%s'", home) > 0);
    assert(system(other_path) == 0);
    puts("secret reader tests passed");
    return 0;
}
