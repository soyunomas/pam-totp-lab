#define _GNU_SOURCE

#include "../challenge.h"
#include "../../pam_partial_key/keyfile.h"
#include "../../pam_schedule_totp_override/schedule.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *name)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

int main(void)
{
    static const char config_text[] =
        "version=1\n"
        "default=ignore\n"
        "user=A;days=Mo-Su;time=0800-1400;authorizer=profesor-1\n"
        "user=B;days=Mo-Su;time=1400-2000;authorizer=profesor-1\n";
    struct pso_config config;
    unsigned char key_id[32];
    size_t first[3];
    size_t second[3];
    char template[] = "/tmp/spk-core-XXXXXX";
    char *directory;
    int fd;

    memset(&config, 0, sizeof(config));
    memset(key_id, 0x5a, sizeof(key_id));
    check(pso_parse_authorizer_config(config_text, sizeof(config_text) - 1U,
                                      &config) == 0 &&
              config.rule_count == 2U &&
              strcmp(config.rules[0].secret_name, "profesor-1") == 0 &&
              strcmp(config.rules[1].secret_name, "profesor-1") == 0,
          "authorizer config accepts explicit reuse");
    check(pso_parse_config(config_text, sizeof(config_text) - 1U, &config) != 0,
          "TOTP parser rejects authorizer field");
    check(pso_validate_authorizer_name("../root") != 0 &&
              pso_validate_authorizer_name("profesor-1") == 0,
          "authorizer names are closed");

    directory = mkdtemp(template);
    check(directory != NULL, "temporary state directory");
    if (directory != NULL) {
        fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        check(fd >= 0, "open state directory");
        if (fd >= 0) {
            check(spk_reserve_challenge_at(fd, geteuid(), 1000U, "A", "sshd",
                                           "profesor-1", key_id, 8U,
                                           first) == SPK_CHALLENGE_OK,
                  "reserve first challenge");
            check(spk_reserve_challenge_at(fd, geteuid(), 1000U, "A", "sshd",
                                           "profesor-1", key_id, 8U,
                                           second) == SPK_CHALLENGE_OK,
                  "reserve second challenge");
            check(memcmp(first, second, sizeof(first)) != 0,
                  "accepted challenge is not emitted twice");
            {
                int pipes[2];
                size_t concurrent[8][3];
                int children_ok = pipe(pipes) == 0;
                memset(concurrent, 0, sizeof(concurrent));
                if (children_ok != 0) {
                    for (size_t child_index = 0U; child_index < 8U;
                         child_index++) {
                        pid_t child = fork();
                        if (child == 0) {
                            size_t value[3];
                            int child_fd;
                            close(pipes[0]);
                            child_fd = open(directory,
                                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                            if (child_fd < 0 ||
                                spk_reserve_challenge_at(
                                    child_fd, geteuid(), 1000U, "A", "sshd",
                                    "profesor-1", key_id, 8U, value) !=
                                    SPK_CHALLENGE_OK ||
                                write(pipes[1], value, sizeof(value)) !=
                                    (ssize_t)sizeof(value)) {
                                _exit(EXIT_FAILURE);
                            }
                            close(child_fd);
                            _exit(EXIT_SUCCESS);
                        }
                        if (child < 0) children_ok = 0;
                    }
                    close(pipes[1]);
                    for (size_t i = 0U; i < 8U; i++) {
                        size_t received = 0U;
                        while (received < sizeof(concurrent[i])) {
                            ssize_t count = read(
                                pipes[0], (unsigned char *)concurrent[i] + received,
                                sizeof(concurrent[i]) - received);
                            if (count <= 0) {
                                children_ok = 0;
                                break;
                            }
                            received += (size_t)count;
                        }
                    }
                    close(pipes[0]);
                    for (size_t i = 0U; i < 8U; i++) {
                        int status;
                        if (wait(&status) < 0 || !WIFEXITED(status) ||
                            WEXITSTATUS(status) != EXIT_SUCCESS) {
                            children_ok = 0;
                        }
                    }
                    for (size_t i = 0U; i < 8U; i++) {
                        for (size_t j = i + 1U; j < 8U; j++) {
                            if (memcmp(concurrent[i], concurrent[j],
                                       sizeof(concurrent[i])) == 0) {
                                children_ok = 0;
                            }
                        }
                    }
                }
                check(children_ok != 0,
                      "concurrent processes reserve distinct challenges");
            }
            close(fd);
        }
    }
    if (directory != NULL) {
        DIR *stream = opendir(directory);
        if (stream != NULL) {
            struct dirent *entry;
            while ((entry = readdir(stream)) != NULL) {
                char path[256];
                int count;
                if (strcmp(entry->d_name, ".") == 0 ||
                    strcmp(entry->d_name, "..") == 0) {
                    continue;
                }
                count = snprintf(path, sizeof(path), "%s/%s", directory,
                                 entry->d_name);
                if (count > 0 && (size_t)count < sizeof(path)) {
                    (void)unlink(path);
                }
            }
            closedir(stream);
        }
        (void)rmdir(directory);
    }
    if (failures == 0) puts("schedule partial-key core tests passed");
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
