#include "../pam_2man_totp/pam_2man_totp.c"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define THREAD_COUNT 8

static int lookup_failure;

static void *check_root_group(void *unused)
{
    (void)unused;
    return is_user_privileged("root", "root") ? NULL : &lookup_failure;
}

int main(void)
{
    pthread_t threads[THREAD_COUNT];

    if (!is_user_privileged("root", "root")) {
        fputs("root was not recognized in its primary group\n", stderr);
        return EXIT_FAILURE;
    }
    if (is_user_privileged("user-that-cannot-exist-pam-totp", "root") ||
        is_user_privileged("root", "group-that-cannot-exist-pam-totp")) {
        fputs("nonexistent account or group was accepted\n", stderr);
        return EXIT_FAILURE;
    }

    for (size_t i = 0U; i < THREAD_COUNT; i++) {
        if (pthread_create(&threads[i], NULL, check_root_group, NULL) != 0) {
            fputs("pthread_create failed\n", stderr);
            return EXIT_FAILURE;
        }
    }
    for (size_t i = 0U; i < THREAD_COUNT; i++) {
        void *result = NULL;
        if (pthread_join(threads[i], &result) != 0 || result != NULL) {
            fputs("concurrent group lookup failed\n", stderr);
            return EXIT_FAILURE;
        }
    }

    puts("All 2-man helper tests passed.");
    return EXIT_SUCCESS;
}
