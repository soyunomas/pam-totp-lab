#define _GNU_SOURCE
#include "../rate_limit.h"

#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
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

struct thread_context {
    int dirfd;
    uid_t owner;
    int result;
};

static void *record_failure(void *opaque)
{
    struct thread_context *context = (struct thread_context *)opaque;
    context->result = pso_rate_record_failure_at(context->dirfd, context->owner,
                                                  (uid_t)1001, "login", 2000U);
    return NULL;
}

static void cleanup_directory(int dirfd)
{
    int duplicate = dup(dirfd);
    DIR *directory;
    struct dirent *entry;

    if (duplicate < 0) return;
    directory = fdopendir(duplicate);
    if (directory == NULL) {
        close(duplicate);
        return;
    }
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            (void)unlinkat(dirfd, entry->d_name, 0);
        }
    }
    closedir(directory);
}

int main(void)
{
    char template[] = "/tmp/pso-rate-XXXXXX";
    char *root = mkdtemp(template);
    int dirfd = -1;
    uid_t owner = geteuid();
    pthread_t threads[8];
    struct thread_context contexts[8];

    check(root != NULL, "create rate directory");
    if (root == NULL) return EXIT_FAILURE;
    dirfd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    check(dirfd >= 0, "open rate directory");
    if (dirfd < 0) goto cleanup;

    check(pso_rate_check_at(dirfd, owner, (uid_t)1000, "sshd", 1000U) ==
              PSO_RATE_ALLOWED,
          "initial request allowed");
    for (unsigned int i = 0U; i < 4U; i++) {
        check(pso_rate_record_failure_at(dirfd, owner, (uid_t)1000, "sshd",
                                         1000U + i) == PSO_RATE_ALLOWED,
              "failures below threshold allowed");
    }
    check(pso_rate_record_failure_at(dirfd, owner, (uid_t)1000, "sshd", 1004U) ==
              PSO_RATE_BLOCKED,
          "fifth failure blocks");
    check(pso_rate_check_at(dirfd, owner, (uid_t)1000, "sshd", 1100U) ==
              PSO_RATE_BLOCKED,
          "block remains active");
    check(pso_rate_check_at(dirfd, owner, (uid_t)1000, "sshd", 1305U) ==
              PSO_RATE_ALLOWED,
          "block expires");
    check(pso_rate_record_failure_at(dirfd, owner, (uid_t)1000, "sshd", 1400U) ==
              PSO_RATE_ALLOWED,
          "new window starts after expiry");
    check(pso_rate_reset_at(dirfd, owner, (uid_t)1000, "sshd") ==
              PSO_RATE_ALLOWED &&
              pso_rate_check_at(dirfd, owner, (uid_t)1000, "sshd", 1401U) ==
                  PSO_RATE_ALLOWED,
          "successful authorization resets limiter");
    check(pso_rate_record_failure_at(dirfd, owner, (uid_t)1000, "bad/service",
                                     1402U) == PSO_RATE_ERROR,
          "invalid service rejected");
    check(pso_rate_check_at(dirfd, owner + (uid_t)1, (uid_t)1000, "sshd", 1402U) ==
              PSO_RATE_ERROR,
          "wrong directory owner rejected");

    memset(contexts, 0, sizeof(contexts));
    for (size_t i = 0U; i < 8U; i++) {
        contexts[i].dirfd = dirfd;
        contexts[i].owner = owner;
        check(pthread_create(&threads[i], NULL, record_failure, &contexts[i]) == 0,
              "create concurrent limiter thread");
    }
    for (size_t i = 0U; i < 8U; i++) {
        check(pthread_join(threads[i], NULL) == 0,
              "join concurrent limiter thread");
        check(contexts[i].result == PSO_RATE_ALLOWED ||
                  contexts[i].result == PSO_RATE_BLOCKED,
              "concurrent update returns valid result");
    }
    check(pso_rate_check_at(dirfd, owner, (uid_t)1001, "login", 2001U) ==
              PSO_RATE_BLOCKED,
          "concurrent failures cannot bypass threshold");

cleanup:
    if (dirfd >= 0) {
        cleanup_directory(dirfd);
        close(dirfd);
    }
    (void)rmdir(root);
    if (failures != 0) return EXIT_FAILURE;
    puts("rate limit tests passed");
    return EXIT_SUCCESS;
}
