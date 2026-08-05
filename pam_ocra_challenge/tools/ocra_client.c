#define _GNU_SOURCE

#include "ocra_client.h"

#include "../ocra_core.h"
#include "../secret_store.h"
#include "../secure_memory.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define OCRA_CLIENT_DIRECTORY "pam-ocra-client"
#define OCRA_CLIENT_PROFILE_MAX_LENGTH 64U

#ifdef OCRA_TESTING
static ocra_client_stat_provider client_test_stat_provider = fstat;
#endif

static int client_fstat(int fd, struct stat *status)
{
#ifdef OCRA_TESTING
    return client_test_stat_provider(fd, status);
#else
    return fstat(fd, status);
#endif
}

static int client_validate_directory_fd(int fd)
{
    struct stat status;

    return client_fstat(fd, &status) == 0 && S_ISDIR(status.st_mode) &&
                   status.st_uid == geteuid() && (status.st_mode & 0022) == 0
               ? 0
               : -1;
}

static int client_validate_profile_file(int fd, struct stat *status)
{
    return client_fstat(fd, status) == 0 && S_ISREG(status->st_mode) &&
                   status->st_nlink == 1 && (status->st_mode & 07777) == 0600 &&
                   status->st_uid == geteuid()
               ? 0
               : -1;
}

static int client_metadata_unchanged(const struct stat *before,
                                     const struct stat *after)
{
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino &&
                   before->st_mode == after->st_mode &&
                   before->st_nlink == after->st_nlink &&
                   before->st_uid == after->st_uid &&
                   before->st_gid == after->st_gid &&
                   before->st_size == after->st_size &&
                   before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
                   before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
                   before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
                   before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
}

static int client_validate_profile_name(const char *profile)
{
    size_t index;

    if (profile == NULL || profile[0] == '\0') {
        return -1;
    }
    for (index = 0U; profile[index] != '\0'; ++index) {
        unsigned char byte = (unsigned char)profile[index];

        if (index >= OCRA_CLIENT_PROFILE_MAX_LENGTH ||
            !((byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') ||
              (byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
              (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              byte == (unsigned char)'_' || byte == (unsigned char)'-')) {
            return -1;
        }
    }
    return 0;
}

static int client_load_profile_at(int config_fd, const char *profile,
                                  struct ocra_secret_record *record)
{
    unsigned char buffer[OCRA_SECRET_FILE_MAX + 1U];
    char file_name[OCRA_CLIENT_PROFILE_MAX_LENGTH + sizeof(".conf")];
    struct stat initial_status;
    struct stat final_status;
    size_t length = 0U;
    int app_fd = -1;
    int file_fd = -1;
    int result = -1;
    int formatted;

    ocra_secret_record_clear(record);
    memset(buffer, 0, sizeof(buffer));
    if (record == NULL || config_fd < 0 ||
        client_validate_profile_name(profile) != 0) {
        goto cleanup;
    }
    formatted = snprintf(file_name, sizeof(file_name), "%s.conf", profile);
    if (formatted < 0 ||
        (size_t)formatted >= sizeof(file_name) ||
        client_validate_directory_fd(config_fd) != 0) {
        goto cleanup;
    }
    app_fd = openat(config_fd, OCRA_CLIENT_DIRECTORY,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (app_fd < 0 || client_validate_directory_fd(app_fd) != 0) {
        goto cleanup;
    }
    file_fd = openat(app_fd, file_name,
                     O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (file_fd < 0 || client_validate_profile_file(file_fd, &initial_status) !=
                           0) {
        goto cleanup;
    }
    while (length < sizeof(buffer)) {
        ssize_t count = read(file_fd, buffer + length, sizeof(buffer) - length);

        if (count > 0) {
            length += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            goto cleanup;
        }
        break;
    }
    if (length > OCRA_SECRET_FILE_MAX ||
        client_validate_profile_file(file_fd, &final_status) != 0 ||
        !client_metadata_unchanged(&initial_status, &final_status) ||
        ocra_secret_record_parse(buffer, length, record) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (file_fd >= 0) {
        (void)close(file_fd);
    }
    if (app_fd >= 0) {
        (void)close(app_fd);
    }
    secure_memory_clear(buffer, sizeof(buffer));
    if (result != 0) {
        ocra_secret_record_clear(record);
    }
    return result;
}

static int client_read_challenge(FILE *input,
                                 char challenge[OCRA_CHALLENGE_DIGITS + 1U])
{
    size_t length = 0U;
    int character;

    memset(challenge, 0, OCRA_CHALLENGE_DIGITS + 1U);
    while ((character = fgetc(input)) != EOF) {
        if (character == '\003' || character == '\004' || character == '\r' ||
            character < '0' || character > '9' || length >= OCRA_CHALLENGE_DIGITS) {
            secure_memory_clear(challenge, OCRA_CHALLENGE_DIGITS + 1U);
            return -1;
        }
        challenge[length++] = (char)character;
        if (length == OCRA_CHALLENGE_DIGITS) {
            character = fgetc(input);
            if (character != '\n') {
                secure_memory_clear(challenge, OCRA_CHALLENGE_DIGITS + 1U);
                return -1;
            }
            return 0;
        }
    }
    secure_memory_clear(challenge, OCRA_CHALLENGE_DIGITS + 1U);
    return -1;
}

static int client_run(int argc, char *const argv[], FILE *input, FILE *output,
                      FILE *error, int config_fd)
{
    struct ocra_secret_record record;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];
    char response[OCRA_RESPONSE_CAPACITY];
    int result = 1;

    ocra_secret_record_clear(&record);
    memset(challenge, 0, sizeof(challenge));
    memset(response, 0, sizeof(response));
    if (argc != 3 || argv == NULL || argv[1] == NULL || argv[2] == NULL ||
        input == NULL || output == NULL || error == NULL ||
        strcmp(argv[1], "--profile") != 0 ||
        client_validate_profile_name(argv[2]) != 0 ||
        client_load_profile_at(config_fd, argv[2], &record) != 0) {
        (void)fprintf(error, "ocra-client: operation failed\n");
        (void)fflush(error);
        goto cleanup;
    }
    if (fputs("Desafío OCRA: ", output) == EOF || fflush(output) != 0 ||
        client_read_challenge(input, challenge) != 0 ||
        ocra_compute_response(record.secret, sizeof(record.secret), challenge,
                              OCRA_CHALLENGE_DIGITS, response,
                              sizeof(response)) != 0 ||
        fprintf(output, "Respuesta: %s\n", response) < 0 ||
        fflush(output) != 0) {
        (void)fprintf(error, "ocra-client: operation failed\n");
        (void)fflush(error);
        goto cleanup;
    }
    result = 0;

cleanup:
    secure_memory_clear(response, sizeof(response));
    secure_memory_clear(challenge, sizeof(challenge));
    ocra_secret_record_clear(&record);
    return result;
}

#ifndef OCRA_CLIENT_NO_MAIN
static int client_open_absolute_directory(const char *path)
{
    char component[NAME_MAX + 1U];
    const char *cursor;
    int directory_fd = -1;

    if (path == NULL || path[0] != '/') {
        return -1;
    }
    directory_fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0) {
        return -1;
    }
    cursor = path;
    while (*cursor != '\0') {
        size_t length = 0U;
        int next_fd;

        while (*cursor == '/') {
            ++cursor;
        }
        if (*cursor == '\0') {
            break;
        }
        while (cursor[length] != '\0' && cursor[length] != '/') {
            if (length >= NAME_MAX) {
                (void)close(directory_fd);
                return -1;
            }
            component[length] = cursor[length];
            ++length;
        }
        component[length] = '\0';
        if ((length == 1U && component[0] == '.') ||
            (length == 2U && component[0] == '.' && component[1] == '.')) {
            (void)close(directory_fd);
            return -1;
        }
        next_fd = openat(directory_fd, component,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        (void)close(directory_fd);
        if (next_fd < 0) {
            return -1;
        }
        directory_fd = next_fd;
        cursor += length;
    }
    return directory_fd;
}

static int client_open_config_directory(void)
{
    const char *xdg_config = getenv("XDG_CONFIG_HOME");
    const char *home = getenv("HOME");
    int home_fd = -1;
    int config_fd = -1;

    if (xdg_config != NULL && xdg_config[0] != '\0') {
        if (xdg_config[0] != '/') {
            return -1;
        }
        config_fd = client_open_absolute_directory(xdg_config);
        if (config_fd < 0 || client_validate_directory_fd(config_fd) != 0) {
            if (config_fd >= 0) {
                (void)close(config_fd);
            }
            return -1;
        }
        return config_fd;
    }
    if (home == NULL || home[0] != '/') {
        return -1;
    }
    home_fd = client_open_absolute_directory(home);
    if (home_fd < 0 || client_validate_directory_fd(home_fd) != 0) {
        goto cleanup;
    }
    config_fd = openat(home_fd, ".config",
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (config_fd < 0 || client_validate_directory_fd(config_fd) != 0) {
        goto cleanup;
    }
    (void)close(home_fd);
    return config_fd;

cleanup:
    if (config_fd >= 0) {
        (void)close(config_fd);
    }
    if (home_fd >= 0) {
        (void)close(home_fd);
    }
    return -1;
}
#endif

#ifdef OCRA_TESTING
int ocra_client_run_for_tests(int argc, char *const argv[], FILE *input,
                              FILE *output, FILE *error, int config_fd)
{
    return client_run(argc, argv, input, output, error, config_fd);
}

void ocra_client_set_stat_provider_for_tests(ocra_client_stat_provider provider)
{
    client_test_stat_provider = provider == NULL ? fstat : provider;
}

void ocra_client_reset_stat_provider_for_tests(void)
{
    client_test_stat_provider = fstat;
}
#endif

#ifndef OCRA_CLIENT_NO_MAIN
int main(int argc, char *argv[])
{
    int config_fd = client_open_config_directory();
    int result;

    if (config_fd < 0) {
        (void)fprintf(stderr, "ocra-client: operation failed\n");
        return 1;
    }
    result = client_run(argc, argv, stdin, stdout, stderr, config_fd);
    (void)close(config_fd);
    return result;
}
#endif
