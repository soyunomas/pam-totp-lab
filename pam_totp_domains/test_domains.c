#define _GNU_SOURCE

#include "domains.h"
#include "secret_file.h"
#include "../pam_common/totp_replay.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *name)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

static int write_file_at(int dirfd, const char *name, const char *content,
                         mode_t mode)
{
    int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    size_t length = strlen(content);
    if (fd < 0) return -1;
    if (write(fd, content, length) != (ssize_t)length) {
        close(fd);
        return -1;
    }
    return close(fd);
}

static void remove_at_best_effort(int dirfd, const char *name, int flags)
{
    if (unlinkat(dirfd, name, flags) != 0) {
        /* Test cleanup is best-effort and must not hide the test result. */
    }
}

static void remove_directory_best_effort(const char *path)
{
    if (rmdir(path) != 0) {
        /* Test cleanup is best-effort and must not hide the test result. */
    }
}

int main(void)
{
    char template[] = "/tmp/pam-totp-domains-XXXXXX";
    char *root = mkdtemp(template);
    const struct ptd_domain *ssh = ptd_domain_for_service("sshd");
    const struct ptd_domain *sudo_domain = ptd_domain_for_service("sudo");
    uid_t owner = geteuid();
    char secret[PTD_MAX_SECRET_LEN + 1U] = {0};
    int home_fd = -1;
    int domain_fd = -1;

    check(ssh != NULL && sudo_domain != NULL, "known services resolve");
    check(ptd_domain_for_service("SSHd") == NULL, "service names are exact");
    check(ptd_domain_for_service("../sshd") == NULL, "paths are rejected");
    check(ptd_domain_for_service("cron") == NULL, "unknown service rejected");
    check(ptd_validate_base32_secret("JBSWY3DPEHPK3PXP", 16U) == 0,
          "valid Base32 accepted");
    check(ptd_validate_base32_secret("jbswy3dpehpk3pxp", 16U) != 0,
          "lowercase rejected");
    check(ptd_validate_base32_secret("JBSWY3DPEHPK3PX=", 16U) != 0,
          "padding rejected");

    if (root == NULL) return EXIT_FAILURE;
    home_fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    check(home_fd >= 0, "open temporary home");
    if (home_fd < 0) goto cleanup;

    check(mkdirat(home_fd, PTD_SECRET_DIRECTORY, 0700) == 0,
          "create private domain directory");
    domain_fd = openat(home_fd, PTD_SECRET_DIRECTORY,
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    check(domain_fd >= 0, "open domain directory");
    if (domain_fd < 0) goto cleanup;

    check(write_file_at(domain_fd, ssh->secret_file,
                        "JBSWY3DPEHPK3PXP\n", 0600) == 0,
          "create SSH secret");
    check(ptd_read_secret_at(home_fd, owner, ssh, secret, sizeof(secret)) ==
              PTD_SECRET_OK &&
              strcmp(secret, "JBSWY3DPEHPK3PXP") == 0,
          "read valid SSH secret");
    check(ptd_read_secret_at(home_fd, owner, sudo_domain, secret,
                             sizeof(secret)) == PTD_SECRET_NOT_FOUND,
          "missing service secret remains distinct");

    check(fchmodat(domain_fd, ssh->secret_file, 0644, 0) == 0,
          "make secret insecure");
    check(ptd_read_secret_at(home_fd, owner, ssh, secret, sizeof(secret)) ==
              PTD_SECRET_ERROR,
          "insecure permissions rejected");
    check(fchmodat(domain_fd, ssh->secret_file, 0600, 0) == 0,
          "restore secret permissions");

    check(unlinkat(domain_fd, ssh->secret_file, 0) == 0,
          "remove regular secret");
    check(symlinkat("/etc/passwd", domain_fd, ssh->secret_file) == 0,
          "create symlink fixture");
    check(ptd_read_secret_at(home_fd, owner, ssh, secret, sizeof(secret)) ==
              PTD_SECRET_ERROR,
          "secret symlink rejected");
    check(unlinkat(domain_fd, ssh->secret_file, 0) == 0,
          "remove symlink fixture");

    check(totp_replay_check_and_store_at(home_fd, owner, ssh->replay_tag,
                                         (uid_t)1001, UINT64_C(42)) ==
              TOTP_REPLAY_ACCEPTED,
          "first SSH counter accepted");
    check(totp_replay_check_and_store_at(home_fd, owner, ssh->replay_tag,
                                         (uid_t)1001, UINT64_C(42)) ==
              TOTP_REPLAY_DETECTED,
          "SSH replay rejected");
    check(totp_replay_check_and_store_at(home_fd, owner,
                                         sudo_domain->replay_tag, (uid_t)1001,
                                         UINT64_C(42)) == TOTP_REPLAY_ACCEPTED,
          "same counter accepted in independent sudo domain");

cleanup:
    if (domain_fd >= 0) {
        if (ssh != NULL) remove_at_best_effort(domain_fd, ssh->secret_file, 0);
        close(domain_fd);
    }
    if (home_fd >= 0) {
        remove_at_best_effort(home_fd, "ptd_sshd-1001.lock", 0);
        remove_at_best_effort(home_fd, "ptd_sshd-1001.counter", 0);
        remove_at_best_effort(home_fd, "ptd_sudo-1001.lock", 0);
        remove_at_best_effort(home_fd, "ptd_sudo-1001.counter", 0);
        remove_at_best_effort(home_fd, PTD_SECRET_DIRECTORY, AT_REMOVEDIR);
        close(home_fd);
    }
    if (root != NULL) remove_directory_best_effort(root);
    if (failures != 0) return EXIT_FAILURE;
    puts("pam_totp_domains tests passed");
    return EXIT_SUCCESS;
}
