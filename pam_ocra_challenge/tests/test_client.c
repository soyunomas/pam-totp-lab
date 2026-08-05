#define _GNU_SOURCE

#include "../challenge.h"
#include "../ocra_core.h"
#include "../tools/ocra_client.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const char marker_secret[] =
    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";

static dev_t owner_test_device;
static ino_t owner_test_inode;
static unsigned int owner_test_calls;
static int owner_test_alter_uid;

struct client_fixture {
    char root_path[512];
    char config_path[512];
    int config_fd;
    int app_fd;
};

struct client_result {
    int exit_code;
    char output[1024];
    char error[1024];
};

static void require(int condition, const char *message)
{
    if (!condition) {
        (void)fprintf(stderr, "test failure: %s\n", message);
        exit(EXIT_FAILURE);
    }
}

static void write_all(int fd, const char *data, size_t length)
{
    size_t offset = 0U;

    while (offset < length) {
        ssize_t count = write(fd, data + offset, length - offset);

        require(count > 0, "fixture write must succeed");
        offset += (size_t)count;
    }
}

static void fixture_create(struct client_fixture *fixture)
{
    char template[] = ".ocra-client-test-XXXXXX";
    char current_directory[384];
    char *name;

    require(getcwd(current_directory, sizeof(current_directory)) != NULL,
            "working directory must fit fixture path");
    name = mkdtemp(template);
    require(name != NULL, "temporary client root must be created");
    require(snprintf(fixture->root_path, sizeof(fixture->root_path), "%s/%s",
                     current_directory, name) > 0,
            "fixture root path must format");
    require(snprintf(fixture->config_path, sizeof(fixture->config_path),
                     "%s/config", fixture->root_path) > 0,
            "fixture config path must format");
    require(mkdir(fixture->config_path, 0700) == 0,
            "fixture config directory must be created");
    fixture->config_fd = open(fixture->config_path,
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(fixture->config_fd >= 0, "fixture config must open");
    require(mkdirat(fixture->config_fd, "pam-ocra-client", 0700) == 0,
            "fixture application directory must be created");
    fixture->app_fd = openat(fixture->config_fd, "pam-ocra-client",
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(fixture->app_fd >= 0, "fixture application directory must open");
}

static void fixture_destroy(struct client_fixture *fixture)
{
    (void)unlinkat(fixture->app_fd, "valid.conf", 0);
    (void)unlinkat(fixture->app_fd, "other.conf", 0);
    (void)unlinkat(fixture->app_fd, "invalid.conf", 0);
    (void)unlinkat(fixture->app_fd, "link.conf", 0);
    (void)unlinkat(fixture->app_fd, "missing.conf", 0);
    (void)unlinkat(fixture->app_fd, "mode.conf", 0);
    (void)unlinkat(fixture->app_fd, "bad-suite.conf", 0);
    (void)unlinkat(fixture->app_fd, "extra.conf", 0);
    (void)unlinkat(fixture->app_fd, "absent.conf", 0);
    (void)unlinkat(fixture->app_fd, "linkcount.conf", 0);
    (void)unlinkat(fixture->app_fd, "owner.conf", 0);
    (void)unlinkat(fixture->app_fd, "directory.conf", AT_REMOVEDIR);
    require(close(fixture->app_fd) == 0, "application directory must close");
    require(unlinkat(fixture->config_fd, "pam-ocra-client", AT_REMOVEDIR) ==
                0,
            "application directory must be removed");
    require(close(fixture->config_fd) == 0, "config directory must close");
    require(rmdir(fixture->config_path) == 0,
            "config directory must be removed");
    require(rmdir(fixture->root_path) == 0, "fixture root must be removed");
}

static void fixture_write_profile(struct client_fixture *fixture,
                                  const char *name, const char *record,
                                  mode_t mode)
{
    int fd = openat(fixture->app_fd, name, O_WRONLY | O_CREAT | O_EXCL |
                                            O_CLOEXEC,
                    mode);

    require(fd >= 0, "fixture profile must be created");
    require(fchmod(fd, mode) == 0, "fixture profile mode must be set");
    write_all(fd, record, strlen(record));
    require(close(fd) == 0, "fixture profile must close");
}

static void fixture_write_valid_profile(struct client_fixture *fixture,
                                        const char *name, mode_t mode)
{
    char record[512];

    require(snprintf(record, sizeof(record),
                     "version=1\n"
                     "suite=OCRA-1:HOTP-SHA256-8:QN10\n"
                     "key_id=0123456789abcdef\n"
                     "secret=%s\n"
                     "enabled=yes\n",
                     marker_secret) > 0,
            "valid profile record must format");
    fixture_write_profile(fixture, name, record, mode);
}

static void read_pipe(int fd, char *output, size_t output_size)
{
    size_t offset = 0U;

    while (offset + 1U < output_size) {
        ssize_t count = read(fd, output + offset, output_size - offset - 1U);

        if (count == 0) {
            break;
        }
        require(count > 0, "child output must be readable");
        offset += (size_t)count;
    }
    output[offset] = '\0';
}

static struct client_result run_client_arguments(
    const struct client_fixture *fixture, char *const arguments[],
    const char *input)
{
    const char *binary = getenv("OCRA_CLIENT_BIN");
    int input_pipe[2];
    int output_pipe[2];
    int error_pipe[2];
    struct client_result result;
    pid_t child;
    int status;

    require(binary != NULL && binary[0] == '/',
            "test needs an absolute client binary path");
    require(pipe(input_pipe) == 0 && pipe(output_pipe) == 0 &&
                pipe(error_pipe) == 0,
            "client pipes must be created");
    child = fork();
    require(child >= 0, "client process must fork");
    if (child == 0) {
        char config_environment[600];
        char *environment[] = {config_environment, "PATH=/usr/bin:/bin",
                               "ASAN_OPTIONS=detect_leaks=0",
                               "OCRA_SECRET_MARKER=never-read", NULL};

        require(snprintf(config_environment, sizeof(config_environment),
                         "XDG_CONFIG_HOME=%s", fixture->config_path) > 0,
                "child config environment must format");
        (void)close(input_pipe[1]);
        (void)close(output_pipe[0]);
        (void)close(error_pipe[0]);
        require(dup2(input_pipe[0], STDIN_FILENO) >= 0,
                "child standard input must redirect");
        require(dup2(output_pipe[1], STDOUT_FILENO) >= 0,
                "child standard output must redirect");
        require(dup2(error_pipe[1], STDERR_FILENO) >= 0,
                "child standard error must redirect");
        execve(binary, arguments, environment);
        _exit(127);
    }
    (void)close(input_pipe[0]);
    (void)close(output_pipe[1]);
    (void)close(error_pipe[1]);
    write_all(input_pipe[1], input, strlen(input));
    require(close(input_pipe[1]) == 0, "client standard input must close");
    read_pipe(output_pipe[0], result.output, sizeof(result.output));
    read_pipe(error_pipe[0], result.error, sizeof(result.error));
    require(close(output_pipe[0]) == 0 && close(error_pipe[0]) == 0,
            "client output pipes must close");
    require(waitpid(child, &status, 0) == child, "client must terminate");
    result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
    return result;
}

static struct client_result run_client(const struct client_fixture *fixture,
                                       const char *profile,
                                       const char *input)
{
    const char *binary = getenv("OCRA_CLIENT_BIN");
    char *arguments[] = {(char *)binary, "--profile", (char *)profile, NULL};

    return run_client_arguments(fixture, arguments, input);
}

static void require_no_secret_disclosure(const struct client_result *result)
{
    static const char decoded_secret[] = "12345678901234567890123456789012";

    require(strstr(result->output, marker_secret) == NULL,
            "stdout must not disclose the profile secret marker");
    require(strstr(result->error, marker_secret) == NULL,
            "stderr must not disclose the profile secret marker");
    require(strstr(result->output, "never-read") == NULL &&
                strstr(result->error, "never-read") == NULL,
            "client must not disclose the environment secret marker");
    require(strstr(result->output, decoded_secret) == NULL &&
                strstr(result->error, decoded_secret) == NULL,
            "client must not disclose the decoded secret material");
}

static void test_valid_profile_runs_real_cli_and_preserves_leading_zeroes(void)
{
    struct client_fixture fixture;
    struct client_result result;
    static const unsigned char verifier_secret[] =
        "12345678901234567890123456789012";
    char independently_verified[OCRA_RESPONSE_CAPACITY];

    fixture_create(&fixture);
    fixture_write_valid_profile(&fixture, "valid.conf", 0600);
    result = run_client(&fixture, "valid", "0000000001\n");
    require(ocra_compute_response(verifier_secret, sizeof(verifier_secret) - 1U,
                                  "0000000001", OCRA_CHALLENGE_DIGITS,
                                  independently_verified,
                                  sizeof(independently_verified)) == 0 &&
                strcmp(independently_verified, "06510410") == 0,
            "independent verifier must accept the e2e response");
    require(result.exit_code == 0, "valid profile and challenge must succeed");
    require(strcmp(result.output, "Desafío OCRA: Respuesta: 06510410\n") ==
                0,
            "client must print the eight-digit OCRA response including zeroes");
    require(result.error[0] == '\0', "successful client must not emit errors");
    require_no_secret_disclosure(&result);
    fixture_destroy(&fixture);
}

static void test_e2e_generated_challenge_is_accepted_by_the_core_verifier(void)
{
    struct client_fixture fixture;
    struct client_result result;
    static const unsigned char verifier_secret[] =
        "12345678901234567890123456789012";
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];
    char input[OCRA_CHALLENGE_DIGITS + 2U];
    char response[OCRA_RESPONSE_CAPACITY];
    char expected_output[128];

    require(ocra_generate_challenge(challenge) == 0,
            "e2e challenge generation must succeed");
    require(snprintf(input, sizeof(input), "%s\n", challenge) > 0,
            "e2e challenge input must format");
    require(ocra_compute_response(verifier_secret, sizeof(verifier_secret) - 1U,
                                  challenge, OCRA_CHALLENGE_DIGITS, response,
                                  sizeof(response)) == 0,
            "independent core verifier must calculate the generated challenge");
    require(snprintf(expected_output, sizeof(expected_output),
                     "Desafío OCRA: Respuesta: %s\n", response) > 0,
            "e2e expected output must format");
    fixture_create(&fixture);
    fixture_write_valid_profile(&fixture, "valid.conf", 0600);
    result = run_client(&fixture, "valid", input);
    require(result.exit_code == 0,
            "client must answer a generated challenge end to end");
    require(strcmp(result.output, expected_output) == 0,
            "core verifier must accept the client e2e response");
    require_no_secret_disclosure(&result);
    fixture_destroy(&fixture);
}

static void test_cli_flushes_prompt_before_receiving_the_challenge(void)
{
    struct client_fixture fixture;
    const char *binary = getenv("OCRA_CLIENT_BIN");
    char *arguments[] = {(char *)binary, "--profile", "valid", NULL};
    char config_environment[600];
    char *environment[] = {config_environment, "PATH=/usr/bin:/bin",
                           "ASAN_OPTIONS=detect_leaks=0", NULL};
    struct pollfd output_ready;
    char prompt[32];
    char remainder[64];
    char error[64];
    int input_pipe[2];
    int output_pipe[2];
    int error_pipe[2];
    int status;
    pid_t child;
    ssize_t count;

    fixture_create(&fixture);
    fixture_write_valid_profile(&fixture, "valid.conf", 0600);
    require(binary != NULL && binary[0] == '/',
            "interactive test needs an absolute client binary path");
    require(snprintf(config_environment, sizeof(config_environment),
                     "XDG_CONFIG_HOME=%s", fixture.config_path) > 0,
            "interactive client config environment must format");
    require(pipe(input_pipe) == 0 && pipe(output_pipe) == 0 &&
                pipe(error_pipe) == 0,
            "interactive client pipes must be created");
    child = fork();
    require(child >= 0, "interactive client process must fork");
    if (child == 0) {
        (void)close(input_pipe[1]);
        (void)close(output_pipe[0]);
        (void)close(error_pipe[0]);
        if (dup2(input_pipe[0], STDIN_FILENO) < 0 ||
            dup2(output_pipe[1], STDOUT_FILENO) < 0 ||
            dup2(error_pipe[1], STDERR_FILENO) < 0) {
            _exit(127);
        }
        execve(binary, arguments, environment);
        _exit(127);
    }
    (void)close(input_pipe[0]);
    (void)close(output_pipe[1]);
    (void)close(error_pipe[1]);
    output_ready.fd = output_pipe[0];
    output_ready.events = POLLIN;
    output_ready.revents = 0;
    require(poll(&output_ready, 1U, 1000) == 1 &&
                (output_ready.revents & POLLIN) != 0,
            "client must flush its prompt before input is supplied");
    count = read(output_pipe[0], prompt, sizeof(prompt) - 1U);
    require(count == (ssize_t)(sizeof("Desafío OCRA: ") - 1U),
            "client must emit only the prompt before receiving input");
    prompt[count] = '\0';
    require(strcmp(prompt, "Desafío OCRA: ") == 0,
            "client prompt must precede the challenge input");
    write_all(input_pipe[1], "0000000001\n", 11U);
    require(close(input_pipe[1]) == 0,
            "interactive challenge input must close");
    read_pipe(output_pipe[0], remainder, sizeof(remainder));
    read_pipe(error_pipe[0], error, sizeof(error));
    require(close(output_pipe[0]) == 0 && close(error_pipe[0]) == 0,
            "interactive client output pipes must close");
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
                WEXITSTATUS(status) == 0,
            "interactive client must succeed after receiving the challenge");
    require(strcmp(remainder, "Respuesta: 06510410\n") == 0 && error[0] == '\0',
            "client must emit only the response after the challenge");
    fixture_destroy(&fixture);
}

static void test_cli_rejects_missing_or_extra_options(void)
{
    struct client_fixture fixture;
    struct client_result result;
    const char *binary = getenv("OCRA_CLIENT_BIN");
    char *missing[] = {(char *)binary, NULL};
    char *wrong_option[] = {(char *)binary, "--secret", "never-read", NULL};
    char *extra[] = {(char *)binary, "--profile", "valid", "extra", NULL};

    fixture_create(&fixture);
    fixture_write_valid_profile(&fixture, "valid.conf", 0600);
    result = run_client_arguments(&fixture, missing, "0000000001\n");
    require(result.exit_code != 0, "missing profile option must fail closed");
    require_no_secret_disclosure(&result);
    result = run_client_arguments(&fixture, wrong_option, "0000000001\n");
    require(result.exit_code != 0, "secret-like option must not be accepted");
    require_no_secret_disclosure(&result);
    result = run_client_arguments(&fixture, extra, "0000000001\n");
    require(result.exit_code != 0, "extra CLI arguments must fail closed");
    require_no_secret_disclosure(&result);
    fixture_destroy(&fixture);
}

static void test_cli_rejects_unavailable_or_unsafe_profiles(void)
{
    struct client_fixture fixture;
    struct client_result result;
    char moved_config_path[512];

    fixture_create(&fixture);
    fixture_write_valid_profile(&fixture, "valid.conf", 0600);
    result = run_client(&fixture, "missing", "0000000001\n");
    require(result.exit_code != 0, "missing profile must fail closed");
    require_no_secret_disclosure(&result);
    require(chmod(fixture.config_path, 0775) == 0,
            "unsafe config directory mode must be settable");
    result = run_client(&fixture, "valid", "0000000001\n");
    require(result.exit_code != 0,
            "group-writable config directory must fail closed");
    require_no_secret_disclosure(&result);
    require(chmod(fixture.config_path, 0700) == 0,
            "safe config directory mode must restore");
    require(snprintf(moved_config_path, sizeof(moved_config_path),
                     "%s/config-real", fixture.root_path) > 0,
            "moved config path must format");
    require(rename(fixture.config_path, moved_config_path) == 0 &&
                symlink("config-real", fixture.config_path) == 0,
            "config directory symlink fixture must be created");
    result = run_client(&fixture, "valid", "0000000001\n");
    require(result.exit_code != 0,
            "XDG config directory symlink must fail closed");
    require_no_secret_disclosure(&result);
    require(unlink(fixture.config_path) == 0 &&
                rename(moved_config_path, fixture.config_path) == 0,
            "config directory must restore after symlink test");
    fixture_write_valid_profile(&fixture, "mode.conf", 0644);
    result = run_client(&fixture, "mode", "0000000001\n");
    require(result.exit_code != 0, "profile mode other than 0600 must fail");
    require_no_secret_disclosure(&result);
    require(renameat(fixture.config_fd, "pam-ocra-client", fixture.config_fd,
                     "saved-directory") == 0,
            "application directory must move for symlink test");
    require(symlinkat("saved-directory", fixture.config_fd,
                      "pam-ocra-client") == 0,
            "application directory symlink must be created");
    result = run_client(&fixture, "valid", "0000000001\n");
    require(result.exit_code != 0,
            "application directory symlink must fail closed");
    require_no_secret_disclosure(&result);
    require(unlinkat(fixture.config_fd, "pam-ocra-client", 0) == 0 &&
                renameat(fixture.config_fd, "saved-directory", fixture.config_fd,
                         "pam-ocra-client") == 0,
            "application directory must restore after symlink test");
    require(symlinkat("valid.conf", fixture.app_fd, "link.conf") == 0,
            "profile symlink fixture must be created");
    result = run_client(&fixture, "link", "0000000001\n");
    require(result.exit_code != 0, "profile symlink must fail closed");
    require_no_secret_disclosure(&result);
    result = run_client(&fixture, "../valid", "0000000001\n");
    require(result.exit_code != 0, "traversal profile name must fail closed");
    require_no_secret_disclosure(&result);
    fixture_destroy(&fixture);
}

static int fstat_with_wrong_profile_owner(int fd, struct stat *status)
{
    int result = fstat(fd, status);

    if (result == 0 && status->st_dev == owner_test_device &&
        status->st_ino == owner_test_inode) {
        ++owner_test_calls;
        if (owner_test_alter_uid != 0) {
            status->st_uid =
                status->st_uid == (uid_t)0 ? (uid_t)1 : (uid_t)0;
        }
    }
    return result;
}

static void test_client_rejects_unsafe_profile_metadata(void)
{
    struct client_fixture fixture;
    struct client_result result;
    struct stat status;
    const char *arguments[] = {"ocra-client", "--profile", "owner", NULL};
    FILE *input;
    FILE *output;
    FILE *error;

    fixture_create(&fixture);
    fixture_write_valid_profile(&fixture, "valid.conf", 0600);
    require(linkat(fixture.app_fd, "valid.conf", fixture.app_fd,
                   "linkcount.conf", 0) == 0,
            "hard-linked profile fixture must be created");
    result = run_client(&fixture, "linkcount", "0000000001\n");
    require(result.exit_code != 0,
            "profile with more than one link must fail closed");
    require_no_secret_disclosure(&result);
    require(mkdirat(fixture.app_fd, "directory.conf", 0700) == 0,
            "directory profile fixture must be created");
    result = run_client(&fixture, "directory", "0000000001\n");
    require(result.exit_code != 0, "non-regular profile must fail closed");
    require_no_secret_disclosure(&result);
    fixture_write_valid_profile(&fixture, "owner.conf", 0600);
    require(fstatat(fixture.app_fd, "owner.conf", &status, 0) == 0,
            "isolated owner profile metadata must load");
    owner_test_device = status.st_dev;
    owner_test_inode = status.st_ino;
    owner_test_alter_uid = 0;
    owner_test_calls = 0U;
    ocra_client_set_stat_provider_for_tests(fstat_with_wrong_profile_owner);
    input = fmemopen("0000000001\n", 11U, "r");
    output = tmpfile();
    error = tmpfile();
    require(input != NULL && output != NULL && error != NULL,
            "unmodified owner streams must be created");
    require(ocra_client_run_for_tests(3, (char *const *)arguments, input,
                                      output, error, fixture.config_fd) == 0 &&
                owner_test_calls != 0U,
            "isolated owner profile must reach metadata validation and succeed");
    require(fclose(input) == 0 && fclose(output) == 0 && fclose(error) == 0,
            "unmodified owner streams must close");
    owner_test_alter_uid = 1;
    owner_test_calls = 0U;
    input = fmemopen("0000000001\n", 11U, "r");
    output = tmpfile();
    error = tmpfile();
    require(input != NULL && output != NULL && error != NULL,
            "owner mismatch streams must be created");
    require(ocra_client_run_for_tests(3, (char *const *)arguments, input,
                                      output, error, fixture.config_fd) != 0 &&
                owner_test_calls != 0U,
            "wrong effective owner must fail closed");
    ocra_client_reset_stat_provider_for_tests();
    require(fclose(input) == 0 && fclose(output) == 0 && fclose(error) == 0,
            "owner mismatch streams must close");
    fixture_destroy(&fixture);
}

static void test_cli_rejects_invalid_profile_format(void)
{
    struct client_fixture fixture;
    struct client_result result;
    char bad_suite[512];
    char extra[512];

    fixture_create(&fixture);
    require(snprintf(bad_suite, sizeof(bad_suite),
                     "version=1\n"
                     "suite=OCRA-1:HOTP-SHA1-6:QN08\n"
                     "key_id=0123456789abcdef\n"
                     "secret=%s\n"
                     "enabled=yes\n",
                     marker_secret) > 0,
            "bad-suite profile must format");
    fixture_write_profile(&fixture, "bad-suite.conf", bad_suite, 0600);
    result = run_client(&fixture, "bad-suite", "0000000001\n");
    require(result.exit_code != 0, "unknown OCRA suite must fail closed");
    require_no_secret_disclosure(&result);
    require(snprintf(extra, sizeof(extra),
                     "version=1\n"
                     "suite=OCRA-1:HOTP-SHA256-8:QN10\n"
                     "key_id=0123456789abcdef\n"
                     "secret=%s\n"
                     "enabled=yes\n"
                     "extra=no\n",
                     marker_secret) > 0,
            "extra-field profile must format");
    fixture_write_profile(&fixture, "extra.conf", extra, 0600);
    result = run_client(&fixture, "extra", "0000000001\n");
    require(result.exit_code != 0, "extra profile field must fail closed");
    require_no_secret_disclosure(&result);
    fixture_write_profile(&fixture, "absent.conf",
                          "version=1\n"
                          "suite=OCRA-1:HOTP-SHA256-8:QN10\n"
                          "key_id=0123456789abcdef\n"
                          "enabled=yes\n",
                          0600);
    result = run_client(&fixture, "absent", "0000000001\n");
    require(result.exit_code != 0, "profile without secret must fail closed");
    require_no_secret_disclosure(&result);
    fixture_destroy(&fixture);
}

static void require_invalid_challenge(const struct client_fixture *fixture,
                                      const char *input, const char *message)
{
    struct client_result result = run_client(fixture, "valid", input);

    require(result.exit_code != 0, message);
    require_no_secret_disclosure(&result);
}

static ssize_t read_failure(void *cookie, char *buffer, size_t size)
{
    (void)cookie;
    (void)buffer;
    (void)size;
    errno = EIO;
    return -1;
}

static void test_client_rejects_invalid_challenge_eof_cancellation_and_io(void)
{
    struct client_fixture fixture;
    static const cookie_io_functions_t failing_read = {.read = read_failure,
                                                        .write = NULL,
                                                        .seek = NULL,
                                                        .close = NULL};
    const char *arguments[] = {"ocra-client", "--profile", "valid", NULL};
    FILE *input;
    FILE *output;
    FILE *error;

    fixture_create(&fixture);
    fixture_write_valid_profile(&fixture, "valid.conf", 0600);
    require_invalid_challenge(&fixture, "123456789\n",
                              "short challenge must fail closed");
    require_invalid_challenge(&fixture, "12345678901\n",
                              "long challenge must fail closed");
    require_invalid_challenge(&fixture, "123456789a\n",
                              "non-decimal challenge must fail closed");
    require_invalid_challenge(&fixture, "0000000001",
                              "challenge EOF without newline must fail closed");
    require_invalid_challenge(&fixture, "\003",
                              "interactive cancellation must fail closed");
    input = fopencookie(NULL, "r", failing_read);
    output = tmpfile();
    error = tmpfile();
    require(input != NULL && output != NULL && error != NULL,
            "I/O failure streams must be created");
    require(ocra_client_run_for_tests(3, (char *const *)arguments, input,
                                      output, error, fixture.config_fd) != 0,
            "input I/O failure must fail closed");
    require(fclose(input) == 0 && fclose(output) == 0 && fclose(error) == 0,
            "I/O failure streams must close");
    fixture_destroy(&fixture);
}

int main(void)
{
    test_valid_profile_runs_real_cli_and_preserves_leading_zeroes();
    test_cli_flushes_prompt_before_receiving_the_challenge();
    test_e2e_generated_challenge_is_accepted_by_the_core_verifier();
    test_cli_rejects_missing_or_extra_options();
    test_cli_rejects_unavailable_or_unsafe_profiles();
    test_client_rejects_unsafe_profile_metadata();
    test_cli_rejects_invalid_profile_format();
    test_client_rejects_invalid_challenge_eof_cancellation_and_io();
    return EXIT_SUCCESS;
}
