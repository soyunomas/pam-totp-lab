#define _GNU_SOURCE

#include "../pam_common/totp_replay.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHILDREN 8
#define NAME_SIZE 96U

static int failures = 0;

static void expect_result(const char *name, int actual, int expected)
{
    if (actual != expected) {
        fprintf(stderr, "FAIL %s: got %d, expected %d\n", name, actual,
                expected);
        failures++;
    }
}

static int make_name(char *buffer, size_t buffer_size, const char *module_tag,
                     uid_t user_id, const char *suffix)
{
    int length = snprintf(buffer, buffer_size, "%s-%" PRIuMAX ".%s",
                          module_tag, (uintmax_t)user_id, suffix);
    return length >= 0 && (size_t)length < buffer_size ? 0 : -1;
}

static int create_file(int directory_fd, const char *name, const char *content,
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

static void remove_state_pair(int directory_fd, const char *module_tag,
                              uid_t user_id)
{
    char name[NAME_SIZE];

    if (make_name(name, sizeof(name), module_tag, user_id, "counter") == 0) {
        (void)unlinkat(directory_fd, name, 0);
    }
    if (make_name(name, sizeof(name), module_tag, user_id, "lock") == 0) {
        (void)unlinkat(directory_fd, name, 0);
    }
}

static void test_ordering(int directory_fd, uid_t owner)
{
    const uid_t user_id = (uid_t)1001;

    expect_result("first counter",
                  totp_replay_check_and_store_at(directory_fd, owner, "basic",
                                                 user_id, UINT64_C(42)),
                  TOTP_REPLAY_ACCEPTED);
    expect_result("same counter",
                  totp_replay_check_and_store_at(directory_fd, owner, "basic",
                                                 user_id, UINT64_C(42)),
                  TOTP_REPLAY_DETECTED);
    expect_result("lower counter",
                  totp_replay_check_and_store_at(directory_fd, owner, "basic",
                                                 user_id, UINT64_C(41)),
                  TOTP_REPLAY_DETECTED);
    expect_result("higher counter",
                  totp_replay_check_and_store_at(directory_fd, owner, "basic",
                                                 user_id, UINT64_C(43)),
                  TOTP_REPLAY_ACCEPTED);
}

static void test_maximum_counter(int directory_fd, uid_t owner)
{
    const uid_t user_id = (uid_t)1002;

    expect_result("maximum counter",
                  totp_replay_check_and_store_at(directory_fd, owner, "max",
                                                 user_id, UINT64_MAX),
                  TOTP_REPLAY_ACCEPTED);
    expect_result("maximum replay",
                  totp_replay_check_and_store_at(directory_fd, owner, "max",
                                                 user_id, UINT64_MAX),
                  TOTP_REPLAY_DETECTED);
}

static void test_corrupt_and_interrupted_state(int directory_fd, uid_t owner)
{
    char name[NAME_SIZE];
    const uid_t corrupt_user = (uid_t)1003;
    const uid_t empty_user = (uid_t)1004;

    if (make_name(name, sizeof(name), "corrupt", corrupt_user, "counter") != 0 ||
        create_file(directory_fd, name, "broken\n", (mode_t)0600) != 0) {
        fprintf(stderr, "FAIL could not create corrupt fixture\n");
        failures++;
    } else {
        expect_result("corrupt state fails closed",
                      totp_replay_check_and_store_at(
                          directory_fd, owner, "corrupt", corrupt_user,
                          UINT64_C(50)),
                      TOTP_REPLAY_ERROR);
    }

    if (make_name(name, sizeof(name), "empty", empty_user, "counter") != 0 ||
        create_file(directory_fd, name, "", (mode_t)0600) != 0) {
        fprintf(stderr, "FAIL could not create empty fixture\n");
        failures++;
    } else {
        expect_result("interrupted first write fails closed",
                      totp_replay_check_and_store_at(
                          directory_fd, owner, "empty", empty_user,
                          UINT64_C(50)),
                      TOTP_REPLAY_ERROR);
    }
}

static void test_symlink_rejected(int directory_fd, uid_t owner)
{
    char name[NAME_SIZE];
    const uid_t user_id = (uid_t)1005;

    if (make_name(name, sizeof(name), "symlink", user_id, "counter") != 0 ||
        symlinkat("nonexistent-target", directory_fd, name) != 0) {
        fprintf(stderr, "FAIL could not create symlink fixture\n");
        failures++;
        return;
    }
    expect_result("state symlink rejected",
                  totp_replay_check_and_store_at(directory_fd, owner, "symlink",
                                                 user_id, UINT64_C(50)),
                  TOTP_REPLAY_ERROR);
}

static void test_input_and_owner_validation(int directory_fd, uid_t owner)
{
    expect_result("path traversal tag rejected",
                  totp_replay_check_and_store_at(directory_fd, owner, "../bad",
                                                 (uid_t)1006, UINT64_C(1)),
                  TOTP_REPLAY_ERROR);
    expect_result("wrong directory owner rejected",
                  totp_replay_check_and_store_at(
                      directory_fd, owner == (uid_t)0 ? (uid_t)1 : (uid_t)0,
                      "owner", (uid_t)1006, UINT64_C(1)),
                  TOTP_REPLAY_ERROR);
}

static void test_concurrency(int directory_fd, uid_t owner)
{
    const uid_t user_id = (uid_t)1007;
    int accepted = 0;
    int replayed = 0;
    int errors = 0;
    int spawned = 0;

    for (int i = 0; i < CHILDREN; i++) {
        pid_t child = fork();
        if (child < 0) {
            fprintf(stderr, "FAIL fork: %s\n", strerror(errno));
            failures++;
            continue;
        }
        if (child == 0) {
            int result = totp_replay_check_and_store_at(
                directory_fd, owner, "parallel", user_id, UINT64_C(99));
            if (result == TOTP_REPLAY_ACCEPTED) _exit(0);
            if (result == TOTP_REPLAY_DETECTED) _exit(10);
            _exit(11);
        }
        spawned++;
    }

    for (int i = 0; i < spawned; i++) {
        int status;
        pid_t child;

        do {
            child = wait(&status);
        } while (child < 0 && errno == EINTR);
        if (child < 0 || !WIFEXITED(status)) {
            errors++;
        } else if (WEXITSTATUS(status) == 0) {
            accepted++;
        } else if (WEXITSTATUS(status) == 10) {
            replayed++;
        } else {
            errors++;
        }
    }

    if (spawned != CHILDREN || accepted != 1 || replayed != spawned - 1 ||
        errors != 0) {
        fprintf(stderr,
                "FAIL concurrent counter: accepted=%d replayed=%d errors=%d\n",
                accepted, replayed, errors);
        failures++;
    }
}

int main(void)
{
    char directory_template[] = "/tmp/pam-totp-replay-XXXXXX";
    char *directory_path = mkdtemp(directory_template);
    int directory_fd;
    uid_t owner = geteuid();

    if (directory_path == NULL) {
        perror("mkdtemp");
        return EXIT_FAILURE;
    }
    directory_fd = open(directory_path,
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0) {
        perror("open temporary directory");
        (void)rmdir(directory_path);
        return EXIT_FAILURE;
    }

    test_ordering(directory_fd, owner);
    test_maximum_counter(directory_fd, owner);
    test_corrupt_and_interrupted_state(directory_fd, owner);
    test_symlink_rejected(directory_fd, owner);
    test_input_and_owner_validation(directory_fd, owner);
    test_concurrency(directory_fd, owner);

    remove_state_pair(directory_fd, "basic", (uid_t)1001);
    remove_state_pair(directory_fd, "max", (uid_t)1002);
    remove_state_pair(directory_fd, "corrupt", (uid_t)1003);
    remove_state_pair(directory_fd, "empty", (uid_t)1004);
    remove_state_pair(directory_fd, "symlink", (uid_t)1005);
    remove_state_pair(directory_fd, "parallel", (uid_t)1007);

    if (close(directory_fd) != 0) {
        perror("close temporary directory");
        failures++;
    }
    if (rmdir(directory_path) != 0) {
        perror("rmdir temporary directory");
        failures++;
    }

    if (failures != 0) return EXIT_FAILURE;
    puts("TOTP anti-replay tests passed");
    return EXIT_SUCCESS;
}
