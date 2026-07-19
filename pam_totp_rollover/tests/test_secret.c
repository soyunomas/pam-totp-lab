#define _GNU_SOURCE

#include "../../pam_common/user_totp_secret.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures = 0;

static void check(int condition, const char *name)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

static int write_file(int directory_fd, const char *name, const char *content,
                      mode_t mode)
{
    int fd = openat(directory_fd, name,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    mode);
    size_t length = strlen(content);
    size_t written = 0U;

    if (fd < 0) return -1;
    while (written < length) {
        ssize_t count = write(fd, content + written, length - written);
        if (count < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (count == 0) {
            close(fd);
            return -1;
        }
        written += (size_t)count;
    }
    return close(fd);
}

int main(void)
{
    char template[] = "/tmp/pam-rollover-secret-XXXXXX";
    char *path = mkdtemp(template);
    char output[USER_TOTP_SECRET_MAX_LENGTH + 1U];
    const char *valid = "JBSWY3DPEHPK3PXP";
    int directory_fd;
    uid_t owner = geteuid();

    if (path == NULL) return EXIT_FAILURE;
    directory_fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0) return EXIT_FAILURE;

    check(user_totp_validate_base32(valid, strlen(valid)) == 0,
          "valid Base32");
    check(user_totp_validate_base32("lowercaseinvalid", 16U) != 0,
          "lowercase rejected");
    check(user_totp_secret_read_at(directory_fd, "missing", owner, output,
                                    sizeof(output)) ==
              USER_TOTP_SECRET_NOT_FOUND,
          "missing secret distinguished");

    check(write_file(directory_fd, "valid", "JBSWY3DPEHPK3PXP\n", 0600) == 0,
          "valid fixture");
    check(user_totp_secret_read_at(directory_fd, "valid", owner, output,
                                    sizeof(output)) == USER_TOTP_SECRET_OK &&
              strcmp(output, valid) == 0,
          "valid secret read");

    check(write_file(directory_fd, "multiline",
                     "JBSWY3DPEHPK3PXP\nJBSWY3DPEHPK3PXP\n", 0600) == 0,
          "multiline fixture");
    check(user_totp_secret_read_at(directory_fd, "multiline", owner, output,
                                    sizeof(output)) == USER_TOTP_SECRET_ERROR,
          "multiline rejected");

    check(write_file(directory_fd, "mode", valid, 0644) == 0,
          "mode fixture");
    check(user_totp_secret_read_at(directory_fd, "mode", owner, output,
                                    sizeof(output)) == USER_TOTP_SECRET_ERROR,
          "insecure mode rejected");

    check(symlinkat("valid", directory_fd, "symlink") == 0,
          "symlink fixture");
    check(user_totp_secret_read_at(directory_fd, "symlink", owner, output,
                                    sizeof(output)) == USER_TOTP_SECRET_ERROR,
          "symlink rejected");

    check(linkat(directory_fd, "valid", directory_fd, "hardlink", 0) == 0,
          "hardlink fixture");
    check(user_totp_secret_read_at(directory_fd, "valid", owner, output,
                                    sizeof(output)) == USER_TOTP_SECRET_ERROR,
          "hardlinked source rejected");

    check(fchmod(directory_fd, 0777) == 0, "make directory insecure");
    check(user_totp_secret_read_at(directory_fd, "mode", owner, output,
                                    sizeof(output)) == USER_TOTP_SECRET_ERROR,
          "insecure directory rejected");
    check(fchmod(directory_fd, 0700) == 0, "restore directory mode");

    (void)unlinkat(directory_fd, "hardlink", 0);
    (void)unlinkat(directory_fd, "symlink", 0);
    (void)unlinkat(directory_fd, "mode", 0);
    (void)unlinkat(directory_fd, "multiline", 0);
    (void)unlinkat(directory_fd, "valid", 0);
    user_totp_secure_memzero(output, sizeof(output));
    check(close(directory_fd) == 0, "close directory");
    check(rmdir(path) == 0, "remove directory");

    if (failures != 0) return EXIT_FAILURE;
    puts("rollover secret tests passed");
    return EXIT_SUCCESS;
}
