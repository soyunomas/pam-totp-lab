#define _GNU_SOURCE

#include "../rate_limit.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PROCESS_COUNT 100U
struct child_result {
    int reserved;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];
};

static void require(int condition, const char *message)
{
    if (!condition) {
        (void)fprintf(stderr, "test failure: %s\n", message);
        exit(EXIT_FAILURE);
    }
}

static void write_all_or_exit(int fd, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    size_t offset = 0U;

    while (offset < length) {
        ssize_t count = write(fd, bytes + offset, length - offset);

        if (count > 0) {
            offset += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            _exit(120);
        }
    }
}

static void read_all(int fd, void *data, size_t length)
{
    unsigned char *bytes = data;
    size_t offset = 0U;

    while (offset < length) {
        ssize_t count = read(fd, bytes + offset, length - offset);

        if (count > 0) {
            offset += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            require(0, "parent must receive every child result");
        }
    }
}

static int fixed_clock(clockid_t clock_id, struct timespec *value)
{
    if (clock_id != CLOCK_MONOTONIC || value == NULL) {
        errno = EINVAL;
        return -1;
    }
    value->tv_sec = (time_t)1000;
    value->tv_nsec = 0L;
    return 0;
}

static int process_unique_challenge(
    char output[OCRA_CHALLENGE_DIGITS + 1U])
{
    uintmax_t value = (uintmax_t)getpid() % UINTMAX_C(10000000000);
    int count = snprintf(output, OCRA_CHALLENGE_DIGITS + 1U, "%010ju", value);

    return count == (int)OCRA_CHALLENGE_DIGITS ? 0 : -1;
}

static void remove_fixture_entries(int root_fd)
{
    DIR *directory;
    struct dirent *entry;
    int scan_fd = dup(root_fd);

    require(scan_fd >= 0, "state root descriptor must duplicate");
    directory = fdopendir(scan_fd);
    require(directory != NULL, "state root descriptor must scan");
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            require(unlinkat(root_fd, entry->d_name, 0) == 0,
                    "concurrency fixture entry must be removed");
        }
        errno = 0;
    }
    require(errno == 0, "state root scan must finish cleanly");
    require(closedir(directory) == 0, "state root scan must close");
}

static void child_run(int root_fd, int start_read_fd, int result_write_fd)
{
    struct child_result result;
    unsigned char token;

    (void)memset(&result, 0, sizeof(result));
    read_all(start_read_fd, &token, sizeof(token));
    result.reserved =
        ocra_rate_limit_reserve_at(root_fd, "1000", "login",
                                   "0123456789abcdef", result.challenge) == 0;
    write_all_or_exit(result_write_fd, &result, sizeof(result));
    _exit(0);
}

int main(void)
{
    char template[] = "/tmp/ocra-rate-concurrency-XXXXXX";
    char *path;
    pid_t children[PROCESS_COUNT];
    int start_pipe[2];
    int result_pipe[2];
    int root_fd;
    unsigned int index;
    unsigned int reserved_count = 0U;
    char authorized[5U][OCRA_CHALLENGE_DIGITS + 1U];
    unsigned char tokens[PROCESS_COUNT];
    char final_challenge[OCRA_CHALLENGE_DIGITS + 1U];

    path = mkdtemp(template);
    require(path != NULL, "concurrency state root must be created");
    require(chmod(path, 0700) == 0,
            "concurrency state root mode must be exact");
    root_fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    require(root_fd >= 0, "concurrency state root must open");
    require(pipe2(start_pipe, O_CLOEXEC) == 0,
            "start barrier pipe must be created");
    require(pipe2(result_pipe, O_CLOEXEC) == 0,
            "result pipe must be created");

    ocra_rate_limit_set_clock_provider_for_tests(fixed_clock);
    ocra_rate_limit_set_challenge_provider_for_tests(process_unique_challenge);
    for (index = 0U; index < PROCESS_COUNT; ++index) {
        children[index] = fork();
        require(children[index] >= 0, "all real worker processes must fork");
        if (children[index] == 0) {
            (void)close(start_pipe[1]);
            (void)close(result_pipe[0]);
            child_run(root_fd, start_pipe[0], result_pipe[1]);
        }
    }
    require(close(start_pipe[0]) == 0,
            "parent start read descriptor must close");
    require(close(result_pipe[1]) == 0,
            "parent result write descriptor must close");
    (void)memset(tokens, 1, sizeof(tokens));
    write_all_or_exit(start_pipe[1], tokens, sizeof(tokens));
    require(close(start_pipe[1]) == 0,
            "parent start barrier must close after release");

    for (index = 0U; index < PROCESS_COUNT; ++index) {
        struct child_result result;

        read_all(result_pipe[0], &result, sizeof(result));
        if (result.reserved != 0) {
            unsigned int prior;

            require(reserved_count < 5U,
                    "never more than five processes may reserve");
            require(strlen(result.challenge) == OCRA_CHALLENGE_DIGITS,
                    "each authorized process must receive ten digits");
            for (prior = 0U; prior < reserved_count; ++prior) {
                require(strcmp(authorized[prior], result.challenge) != 0,
                        "authorized processes must reserve distinct challenges");
            }
            (void)strcpy(authorized[reserved_count], result.challenge);
            ++reserved_count;
        } else {
            require(result.challenge[0] == '\0',
                    "denied process must not receive a challenge");
        }
    }
    require(close(result_pipe[0]) == 0,
            "parent result descriptor must close");
    for (index = 0U; index < PROCESS_COUNT; ++index) {
        int status;

        require(waitpid(children[index], &status, 0) == children[index],
                "every worker process must be reaped");
        require(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "every worker process must exit cleanly");
    }
    require(reserved_count == 5U,
            "exactly five reservations prove increments were not lost");
    require(ocra_rate_limit_reserve_at(root_fd, "1000", "login",
                                       "0123456789abcdef", final_challenge) != 0,
            "the next process must observe the persisted block");

    ocra_rate_limit_reset_clock_provider_for_tests();
    ocra_rate_limit_reset_challenge_provider_for_tests();
    remove_fixture_entries(root_fd);
    require(close(root_fd) == 0, "concurrency state root must close");
    require(rmdir(path) == 0, "concurrency state root must be removed");
    return EXIT_SUCCESS;
}
