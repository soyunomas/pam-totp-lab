#define _GNU_SOURCE

#include "../secret.h"
#include "../slot_policy.h"

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define THREAD_COUNT 16U
#define ITERATIONS 500U

struct worker_context {
    const char *home;
    uid_t uid;
    atomic_int *failed;
};

static void write_secret(const char *path)
{
    static const char value[] = "JBSWY3DPEHPK3PXP\n";
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

    assert(fd >= 0);
    assert(write(fd, value, sizeof(value) - 1U) == (ssize_t)(sizeof(value) - 1U));
    assert(close(fd) == 0);
    assert(chmod(path, 0600) == 0);
}

static void *worker(void *argument)
{
    struct worker_context *context = argument;

    for (size_t i = 0U; i < ITERATIONS; i++) {
        size_t index = PTSC_MAX_SLOTS;
        char secret[PTSC_MAX_SECRET_LEN + 1U];

        if (ptsc_random_index(PTSC_MAX_SLOTS, &index) != 0 ||
            index >= PTSC_MAX_SLOTS ||
            ptsc_read_slot_secret(context->home, context->uid, index, secret,
                                  sizeof(secret)) != PTSC_SECRET_OK ||
            strcmp(secret, "JBSWY3DPEHPK3PXP") != 0) {
            atomic_store(context->failed, 1);
            return NULL;
        }
        ptsc_secure_memzero(secret, sizeof(secret));
    }
    return NULL;
}

int main(void)
{
    char template[] = "/tmp/ptsc-concurrency-XXXXXX";
    char *home = mkdtemp(template);
    char directory[PATH_MAX];
    char path[PATH_MAX];
    char cleanup[PATH_MAX + 32U];
    pthread_t threads[THREAD_COUNT];
    atomic_int failed = 0;
    struct worker_context context;

    assert(home != NULL);
    assert(chmod(home, 0700) == 0);
    assert(snprintf(directory, sizeof(directory), "%s/%s", home,
                    PTSC_SECRET_DIRECTORY) > 0);
    assert(mkdir(directory, 0700) == 0);

    for (size_t i = 0U; i < PTSC_MAX_SLOTS; i++) {
        const struct ptsc_slot *slot = ptsc_slot_by_index(i);

        assert(slot != NULL);
        assert(snprintf(path, sizeof(path), "%s/%s", directory,
                        slot->secret_file) > 0);
        write_secret(path);
    }

    context.home = home;
    context.uid = getuid();
    context.failed = &failed;
    for (size_t i = 0U; i < THREAD_COUNT; i++) {
        assert(pthread_create(&threads[i], NULL, worker, &context) == 0);
    }
    for (size_t i = 0U; i < THREAD_COUNT; i++) {
        assert(pthread_join(threads[i], NULL) == 0);
    }
    assert(atomic_load(&failed) == 0);

    assert(snprintf(cleanup, sizeof(cleanup), "rm -rf -- '%s'", home) > 0);
    assert(system(cleanup) == 0);
    puts("concurrency tests passed");
    return 0;
}
