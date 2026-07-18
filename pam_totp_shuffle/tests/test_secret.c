#define _GNU_SOURCE
#include "../secret.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void write_file(int dirfd, const char *name, const char *content, mode_t mode)
{
    int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    assert(fd >= 0);
    assert(write(fd, content, strlen(content)) == (ssize_t)strlen(content));
    assert(close(fd) == 0);
}

int main(void)
{
    char template[] = "/tmp/pts-secret-XXXXXX";
    char *directory = mkdtemp(template);
    char secret[PTS_MAX_SECRET_LENGTH + 1U];
    int dirfd;
    uid_t uid = geteuid();

    assert(directory != NULL);
    dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(dirfd >= 0);

    write_file(dirfd, "valid", "JBSWY3DPEHPK3PXP\n", 0600);
    assert(pts_read_secret_at(dirfd, "valid", uid, secret, sizeof(secret)) == PTS_SECRET_OK);
    assert(strcmp(secret, "JBSWY3DPEHPK3PXP") == 0);

    write_file(dirfd, "badmode", "JBSWY3DPEHPK3PXP\n", 0644);
    assert(pts_read_secret_at(dirfd, "badmode", uid, secret, sizeof(secret)) == PTS_SECRET_ERROR);

    write_file(dirfd, "lower", "jbswy3dpehpk3pxp\n", 0600);
    assert(pts_read_secret_at(dirfd, "lower", uid, secret, sizeof(secret)) == PTS_SECRET_ERROR);

    write_file(dirfd, "multi", "JBSWY3DPEHPK3PXP\nAAAA\n", 0600);
    assert(pts_read_secret_at(dirfd, "multi", uid, secret, sizeof(secret)) == PTS_SECRET_ERROR);

    assert(symlinkat("valid", dirfd, "link") == 0);
    assert(pts_read_secret_at(dirfd, "link", uid, secret, sizeof(secret)) == PTS_SECRET_ERROR);

    assert(linkat(dirfd, "valid", dirfd, "hard", 0) == 0);
    assert(pts_read_secret_at(dirfd, "valid", uid, secret, sizeof(secret)) == PTS_SECRET_ERROR);

    assert(pts_read_secret_at(dirfd, "missing", uid, secret, sizeof(secret)) == PTS_SECRET_NOT_FOUND);
    assert(pts_read_secret_at(dirfd, "../valid", uid, secret, sizeof(secret)) == PTS_SECRET_ERROR);

    unlinkat(dirfd, "hard", 0);
    unlinkat(dirfd, "link", 0);
    unlinkat(dirfd, "multi", 0);
    unlinkat(dirfd, "lower", 0);
    unlinkat(dirfd, "badmode", 0);
    unlinkat(dirfd, "valid", 0);
    close(dirfd);
    rmdir(directory);

    puts("test_secret: OK");
    return 0;
}
