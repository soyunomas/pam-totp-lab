#define _GNU_SOURCE
#include "../secure_store.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *name)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

static int write_at(int dirfd, const char *name, const char *content, mode_t mode)
{
    int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    size_t length = strlen(content);
    ssize_t count;
    if (fd < 0) return -1;
    count = write(fd, content, length);
    if (count != (ssize_t)length) {
        close(fd);
        return -1;
    }
    return close(fd);
}

int main(void)
{
    char template[] = "/tmp/pso-store-XXXXXX";
    char *root = mkdtemp(template);
    int security_fd = -1;
    int secret_dir_fd = -1;
    uid_t owner = geteuid();
    struct pso_config config;
    char secret[PSO_MAX_SECRET_LEN + 1U];
    static const char config_text[] =
        "version=1\ndefault=deny\n"
        "user=A;days=Mo-Fr;time=0800-1400;secret=A.secret\n";

    check(root != NULL, "create temporary security directory");
    if (root == NULL) return EXIT_FAILURE;
    security_fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    check(security_fd >= 0, "open temporary security directory");
    if (security_fd < 0) goto cleanup;

    check(write_at(security_fd, PSO_CONFIG_FILE, config_text, 0600) == 0,
          "write valid config");
    check(pso_read_config_at(security_fd, owner, &config) == PSO_STORE_OK &&
              config.rule_count == 1U,
          "read valid protected config");
    check(fchmodat(security_fd, PSO_CONFIG_FILE, 0644, 0) == 0,
          "make config world readable");
    check(pso_read_config_at(security_fd, owner, &config) == PSO_STORE_ERROR,
          "reject non-0600 config");
    check(fchmodat(security_fd, PSO_CONFIG_FILE, 0600, 0) == 0,
          "restore config mode");

    check(mkdirat(security_fd, PSO_SECRET_DIRECTORY, 0700) == 0,
          "create secret directory");
    secret_dir_fd = openat(security_fd, PSO_SECRET_DIRECTORY,
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    check(secret_dir_fd >= 0, "open secret directory");
    if (secret_dir_fd < 0) goto cleanup;

    check(write_at(secret_dir_fd, "A.secret", "JBSWY3DPEHPK3PXP\n", 0600) == 0,
          "write valid secret");
    check(pso_read_secret_at(security_fd, owner, "A.secret", secret,
                             sizeof(secret)) == PSO_STORE_OK &&
              strcmp(secret, "JBSWY3DPEHPK3PXP") == 0,
          "read valid secret");
    check(pso_read_secret_at(security_fd, owner, "B.secret", secret,
                             sizeof(secret)) == PSO_STORE_NOT_FOUND,
          "missing secret distinct");

    check(fchmodat(secret_dir_fd, "A.secret", 0644, 0) == 0,
          "make secret insecure");
    check(pso_read_secret_at(security_fd, owner, "A.secret", secret,
                             sizeof(secret)) == PSO_STORE_ERROR,
          "reject insecure secret mode");
    check(fchmodat(secret_dir_fd, "A.secret", 0600, 0) == 0,
          "restore secret mode");

    check(write_at(secret_dir_fd, "A.secret", "jbswy3dpehpk3pxp\n", 0600) == 0,
          "write lowercase secret");
    check(pso_read_secret_at(security_fd, owner, "A.secret", secret,
                             sizeof(secret)) == PSO_STORE_ERROR,
          "reject lowercase Base32");
    check(write_at(secret_dir_fd, "A.secret", "JBSWY3DPEHPK3PX=\n", 0600) == 0,
          "write padded secret");
    check(pso_read_secret_at(security_fd, owner, "A.secret", secret,
                             sizeof(secret)) == PSO_STORE_ERROR,
          "reject Base32 padding");
    check(write_at(secret_dir_fd, "A.secret",
                   "JBSWY3DPEHPK3PXP\nJBSWY3DPEHPK3PXP\n", 0600) == 0,
          "write multiline secret");
    check(pso_read_secret_at(security_fd, owner, "A.secret", secret,
                             sizeof(secret)) == PSO_STORE_ERROR,
          "reject multiline secret");

    check(unlinkat(secret_dir_fd, "A.secret", 0) == 0,
          "remove secret for symlink test");
    check(symlinkat("/etc/passwd", secret_dir_fd, "A.secret") == 0,
          "create secret symlink");
    check(pso_read_secret_at(security_fd, owner, "A.secret", secret,
                             sizeof(secret)) == PSO_STORE_ERROR,
          "reject secret symlink");
    check(unlinkat(secret_dir_fd, "A.secret", 0) == 0,
          "remove secret symlink");

    check(write_at(secret_dir_fd, "A.secret", "JBSWY3DPEHPK3PXP\n", 0600) == 0,
          "restore regular secret");
    check(linkat(secret_dir_fd, "A.secret", secret_dir_fd, "A-copy.secret", 0) == 0,
          "create hard link");
    check(pso_read_secret_at(security_fd, owner, "A.secret", secret,
                             sizeof(secret)) == PSO_STORE_ERROR,
          "reject hard-linked secret");
    check(unlinkat(secret_dir_fd, "A-copy.secret", 0) == 0,
          "remove hard link");

    check(fchmod(secret_dir_fd, 0755) == 0, "make secret directory insecure");
    check(pso_read_secret_at(security_fd, owner, "A.secret", secret,
                             sizeof(secret)) == PSO_STORE_ERROR,
          "reject insecure secret directory");
    check(fchmod(secret_dir_fd, 0700) == 0, "restore secret directory mode");
    check(pso_read_secret_at(security_fd, owner + (uid_t)1, "A.secret", secret,
                             sizeof(secret)) == PSO_STORE_ERROR,
          "reject wrong expected owner");
    check(pso_read_secret_at(security_fd, owner, "../A.secret", secret,
                             sizeof(secret)) == PSO_STORE_ERROR,
          "reject secret path traversal");

cleanup:
    if (secret_dir_fd >= 0) {
        (void)unlinkat(secret_dir_fd, "A-copy.secret", 0);
        (void)unlinkat(secret_dir_fd, "A.secret", 0);
        close(secret_dir_fd);
    }
    if (security_fd >= 0) {
        (void)unlinkat(security_fd, PSO_CONFIG_FILE, 0);
        (void)unlinkat(security_fd, PSO_SECRET_DIRECTORY, AT_REMOVEDIR);
        close(security_fd);
    }
    (void)rmdir(root);

    if (failures != 0) return EXIT_FAILURE;
    puts("secure store tests passed");
    return EXIT_SUCCESS;
}
