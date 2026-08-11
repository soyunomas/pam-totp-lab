#define _GNU_SOURCE

#include "../secret_store.h"
#include "../challenge.h"
#include "../ocra_core.h"
#include "../rate_limit.h"
#include "../tools/ocra_enroll.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/crypto.h>

#define TEST_UID_TEXT "1000"
#define TEST_USER "alice"
#define TEST_SERVICE "sudo"

struct enroll_fixture {
    char root_path[160];
    char server_path[192];
    char client_path[192];
    char profile_path[256];
    char rate_path[192];
    int server_fd;
    int rate_fd;
};

static unsigned int random_call;
static unsigned int secret_random_call;
static unsigned int identifier_random_call;

static void require(int condition, const char *message)
{
    if (!condition) {
        (void)fprintf(stderr, "test failure: %s\n", message);
        exit(EXIT_FAILURE);
    }
}

static int deterministic_random(void *buffer, size_t length)
{
    unsigned char *bytes = buffer;
    size_t index;
    unsigned int sequence;

    require(buffer != NULL, "random provider needs output storage");
    require(length == OCRA_SECRET_BYTES || length == 8U,
            "enrollment randomness must request a secret or an identifier");
    if (length == OCRA_SECRET_BYTES) {
        sequence = secret_random_call++;
    } else {
        sequence = identifier_random_call++;
    }
    for (index = 0U; index < length; ++index) {
        bytes[index] = (unsigned char)(index +
                                       (length == OCRA_SECRET_BYTES
                                            ? sequence * 0x40U
                                            : 0x80U + sequence * 0x10U));
    }
    ++random_call;
    return 0;
}

static ssize_t deterministic_challenge_random(void *buffer, size_t length,
                                              int flags)
{
    uint64_t sample = UINT64_C(1);

    require(buffer != NULL && length == sizeof(sample) && flags == 0,
            "confirmation challenge must request one getrandom sample");
    (void)memcpy(buffer, &sample, sizeof(sample));
    return (ssize_t)sizeof(sample);
}

static int resolve_test_user(const char *name, uid_t *uid, gid_t *gid)
{
    require(name != NULL && uid != NULL && gid != NULL,
            "resolver arguments must be present");
    if (strcmp(name, TEST_USER) != 0) {
        errno = ENOENT;
        return -1;
    }
    *uid = (uid_t)1000;
    *gid = getegid();
    return 0;
}

static int resolve_no_user(const char *name, uid_t *uid, gid_t *gid)
{
    (void)name;
    (void)uid;
    (void)gid;
    errno = ENOENT;
    return -1;
}

static int failing_random(void *buffer, size_t length)
{
    (void)buffer;
    (void)length;
    errno = EIO;
    return -1;
}

static void make_directory(const char *path)
{
    require(mkdir(path, 0700) == 0, "fixture directory must be created");
    require(chmod(path, 0700) == 0, "fixture directory mode must be exact");
}

static void fixture_create(struct enroll_fixture *fixture)
{
    char template[] = "/tmp/ocra-enroll-XXXXXX";
    char *root = mkdtemp(template);

    require(root != NULL, "temporary enrollment root must be created");
    require(strlen(root) < sizeof(fixture->root_path),
            "temporary root path must fit");
    (void)strcpy(fixture->root_path, root);
    require(snprintf(fixture->server_path, sizeof(fixture->server_path),
                     "%s/server", root) > 0,
            "server path must format");
    require(snprintf(fixture->client_path, sizeof(fixture->client_path),
                     "%s/client", root) > 0,
            "client path must format");
    require(snprintf(fixture->rate_path, sizeof(fixture->rate_path),
                     "%s/rate", root) > 0,
            "rate path must format");
    require(snprintf(fixture->profile_path, sizeof(fixture->profile_path),
                     "%s/alice-sudo.conf", fixture->client_path) > 0,
            "profile path must format");
    make_directory(fixture->server_path);
    make_directory(fixture->client_path);
    make_directory(fixture->rate_path);
    if (geteuid() == (uid_t)0) {
        require(chown(fixture->client_path, (uid_t)1000, getegid()) == 0,
                "root harness client directory must belong to test user");
    }
    fixture->server_fd = open(fixture->server_path,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    fixture->rate_fd = open(fixture->rate_path,
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    require(fixture->server_fd >= 0 && fixture->rate_fd >= 0,
            "fixture roots must open");
    random_call = 0U;
    secret_random_call = 0U;
    identifier_random_call = 0U;
    ocra_enroll_set_random_provider_for_tests(deterministic_random);
    ocra_enroll_set_user_provider_for_tests(resolve_test_user);
    ocra_enroll_set_euid_for_tests((uid_t)0);
    ocra_challenge_set_random_provider_for_tests(
        deterministic_challenge_random);
}

static void remove_directory_contents(int directory_fd)
{
    DIR *directory;
    struct dirent *entry;
    int scan_fd = dup(directory_fd);

    require(scan_fd >= 0, "fixture directory descriptor must duplicate");
    directory = fdopendir(scan_fd);
    require(directory != NULL, "fixture directory must scan");
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        struct stat status;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        require(fstatat(directory_fd, entry->d_name, &status,
                        AT_SYMLINK_NOFOLLOW) == 0,
                "fixture entry metadata must load");
        if (S_ISDIR(status.st_mode)) {
            int child_fd = openat(directory_fd, entry->d_name,
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                      O_CLOEXEC);

            require(child_fd >= 0, "fixture child directory must open");
            remove_directory_contents(child_fd);
            require(close(child_fd) == 0,
                    "fixture child directory must close");
            require(unlinkat(directory_fd, entry->d_name, AT_REMOVEDIR) == 0,
                    "fixture child directory must be removed");
        } else {
            require(unlinkat(directory_fd, entry->d_name, 0) == 0,
                    "fixture file must be removed");
        }
        errno = 0;
    }
    require(errno == 0, "fixture scan must finish cleanly");
    require(closedir(directory) == 0, "fixture scan must close");
}

static size_t directory_entry_count(int directory_fd)
{
    DIR *directory;
    struct dirent *entry;
    size_t count = 0U;
    int scan_fd = dup(directory_fd);

    require(scan_fd >= 0, "directory count descriptor must duplicate");
    directory = fdopendir(scan_fd);
    require(directory != NULL, "directory count stream must open");
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            ++count;
        }
        errno = 0;
    }
    require(errno == 0 && closedir(directory) == 0,
            "directory count must finish cleanly");
    return count;
}

static void move_directory_files(const char *source_path,
                                 const char *destination_path)
{
    int source_fd;
    int destination_fd;
    int scan_fd;
    DIR *directory;
    struct dirent *entry;

    source_fd = open(source_path,
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    destination_fd = open(destination_path,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    require(source_fd >= 0 && destination_fd >= 0,
            "identity-test directories must open");
    scan_fd = dup(source_fd);
    require(scan_fd >= 0, "identity-test source descriptor must duplicate");
    directory = fdopendir(scan_fd);
    require(directory != NULL, "identity-test source must scan");
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        require(renameat(source_fd, entry->d_name, destination_fd,
                         entry->d_name) == 0,
                "identity-test participant files must move by descriptor");
        errno = 0;
    }
    require(errno == 0 && closedir(directory) == 0 &&
                close(destination_fd) == 0 && close(source_fd) == 0,
            "identity-test directory move must finish cleanly");
}

static int open_test_server_scope(struct enroll_fixture *fixture)
{
    int users_fd;
    int scope_fd;

    users_fd = openat(fixture->server_fd, "users",
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    require(users_fd >= 0, "test users scope must open");
    scope_fd = openat(users_fd, TEST_UID_TEXT,
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    require(scope_fd >= 0 && close(users_fd) == 0,
            "test UID scope must open and parent close");
    return scope_fd;
}

static void fixture_destroy(struct enroll_fixture *fixture)
{
    int root_fd;

    require(close(fixture->server_fd) == 0, "server root must close");
    require(close(fixture->rate_fd) == 0, "rate root must close");
    ocra_enroll_reset_test_providers();
    ocra_challenge_reset_random_provider_for_tests();
    root_fd = open(fixture->root_path,
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    require(root_fd >= 0, "fixture root must reopen for cleanup");
    remove_directory_contents(root_fd);
    require(close(root_fd) == 0, "fixture root must close after cleanup");
    require(rmdir(fixture->root_path) == 0,
            "temporary fixture root must be removed");
}

static char *read_stream_binary(FILE *stream, size_t *captured_length)
{
    long length;
    char *data;

    require(fflush(stream) == 0, "captured stream must flush");
    require(fseek(stream, 0L, SEEK_END) == 0, "captured stream must seek end");
    length = ftell(stream);
    require(length >= 0, "captured stream length must be known");
    require(fseek(stream, 0L, SEEK_SET) == 0,
            "captured stream must rewind");
    data = calloc((size_t)length + 1U, 1U);
    require(data != NULL, "captured stream buffer must allocate");
    require(fread(data, 1U, (size_t)length, stream) == (size_t)length,
            "captured stream must read completely");
    if (captured_length != NULL) {
        *captured_length = (size_t)length;
    }
    return data;
}

static char *read_stream(FILE *stream)
{
    return read_stream_binary(stream, NULL);
}

static int buffer_contains(const void *buffer, size_t buffer_length,
                           const void *needle, size_t needle_length)
{
    const unsigned char *bytes = buffer;
    size_t offset;

    if (needle_length == 0U || buffer_length < needle_length) {
        return 0;
    }
    for (offset = 0U; offset <= buffer_length - needle_length; ++offset) {
        if (memcmp(bytes + offset, needle, needle_length) == 0) {
            return 1;
        }
    }
    return 0;
}

static int read_pipe_line(int fd, char *buffer, size_t capacity)
{
    size_t length = 0U;

    if (capacity == 0U) {
        return -1;
    }
    while (length + 1U < capacity) {
        ssize_t count = read(fd, buffer + length, 1U);

        if (count == 1) {
            if (buffer[length++] == '\n') {
                buffer[length] = '\0';
                return 0;
            }
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    buffer[length] = '\0';
    return -1;
}

static void test_child_exit(int status)
{
    OPENSSL_cleanup();
    _exit(status);
}

static int run_add(struct enroll_fixture *fixture)
{
    char *arguments[] = {"ocra-enroll", "add", "--user", TEST_USER,
                         "--service", TEST_SERVICE, "--client-profile",
                         fixture->profile_path};
    FILE *input = tmpfile();
    FILE *output = tmpfile();
    FILE *error = tmpfile();
    int result;

    require(input != NULL && output != NULL && error != NULL,
            "add streams must be created");
    result = ocra_enroll_run_at_for_tests(8, arguments, input, output, error,
                                          fixture->server_fd,
                                          fixture->rate_fd);
    require(fclose(input) == 0 && fclose(output) == 0 && fclose(error) == 0,
            "add streams must close");
    return result;
}

static int run_rotate_captured(struct enroll_fixture *fixture,
                               const char *response, char **stdout_text,
                               size_t *stdout_length, char **stderr_text,
                               size_t *stderr_length)
{
    char *arguments[] = {"ocra-enroll", "rotate", "--user", TEST_USER,
                         "--service", TEST_SERVICE, "--client-profile",
                         fixture->profile_path};
    FILE *input = tmpfile();
    FILE *output = tmpfile();
    FILE *error = tmpfile();
    int result;

    require(input != NULL && output != NULL && error != NULL,
            "rotation streams must be created");
    require(fputs(response, input) >= 0 && fflush(input) == 0 &&
                fseek(input, 0L, SEEK_SET) == 0,
            "external confirmation response must be staged on stdin");
    result = ocra_enroll_run_at_for_tests(8, arguments, input, output, error,
                                          fixture->server_fd,
                                          fixture->rate_fd);
    if (stdout_text != NULL) {
        *stdout_text = read_stream_binary(output, stdout_length);
    }
    if (stderr_text != NULL) {
        *stderr_text = read_stream_binary(error, stderr_length);
    }
    require(fclose(input) == 0 && fclose(output) == 0 && fclose(error) == 0,
            "rotation streams must close");
    return result;
}

static int run_rotate(struct enroll_fixture *fixture, const char *response,
                      char **stdout_text, char **stderr_text)
{
    return run_rotate_captured(fixture, response, stdout_text, NULL,
                               stderr_text, NULL);
}

static int run_server_only_command(struct enroll_fixture *fixture,
                                   const char *operation, const char *service,
                                   char **stdout_text, char **stderr_text)
{
    char *arguments[] = {"ocra-enroll", (char *)operation, "--user",
                         TEST_USER, "--service", (char *)service};
    FILE *input = tmpfile();
    FILE *output = tmpfile();
    FILE *error = tmpfile();
    int result;

    require(input != NULL && output != NULL && error != NULL,
            "server-only command streams must be created");
    result = ocra_enroll_run_at_for_tests(6, arguments, input, output, error,
                                          fixture->server_fd,
                                          fixture->rate_fd);
    if (stdout_text != NULL) {
        *stdout_text = read_stream(output);
    }
    if (stderr_text != NULL) {
        *stderr_text = read_stream(error);
    }
    require(fclose(input) == 0 && fclose(output) == 0 && fclose(error) == 0,
            "server-only command streams must close");
    return result;
}

static int run_add_scope(struct enroll_fixture *fixture, const char *service,
                         const char *profile_path)
{
    char *arguments[] = {"ocra-enroll", "add", "--user", TEST_USER,
                         "--service", (char *)service, "--client-profile",
                         (char *)profile_path};
    FILE *input = tmpfile();
    FILE *output = tmpfile();
    FILE *error = tmpfile();
    int result;

    require(input != NULL && output != NULL && error != NULL,
            "scoped add streams must be created");
    result = ocra_enroll_run_at_for_tests(8, arguments, input, output, error,
                                          fixture->server_fd,
                                          fixture->rate_fd);
    require(fclose(input) == 0 && fclose(output) == 0 && fclose(error) == 0,
            "scoped add streams must close");
    return result;
}

static int run_add_overwrite(struct enroll_fixture *fixture,
                             const char *response)
{
    char *arguments[] = {"ocra-enroll", "add", "--user", TEST_USER,
                         "--service", TEST_SERVICE, "--client-profile",
                         fixture->profile_path, "--overwrite"};
    FILE *input = tmpfile();
    FILE *output = tmpfile();
    FILE *error = tmpfile();
    int result;

    require(input != NULL && output != NULL && error != NULL,
            "overwrite streams must be created");
    require(fputs(response, input) >= 0 && fflush(input) == 0 &&
                fseek(input, 0L, SEEK_SET) == 0,
            "overwrite confirmation response must be staged");
    result = ocra_enroll_run_at_for_tests(9, arguments, input, output, error,
                                          fixture->server_fd,
                                          fixture->rate_fd);
    require(fclose(input) == 0 && fclose(output) == 0 && fclose(error) == 0,
            "overwrite streams must close");
    return result;
}

static void load_client_record(struct enroll_fixture *fixture,
                               struct ocra_secret_record *record)
{
    unsigned char data[OCRA_SECRET_FILE_MAX + 1U];
    int fd = open(fixture->profile_path,
                  O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    ssize_t length;

    require(fd >= 0, "client profile must open for parsing");
    length = read(fd, data, sizeof(data));
    require(length > 0 && (size_t)length <= OCRA_SECRET_FILE_MAX,
            "client profile body must be bounded");
    require(close(fd) == 0, "client profile parser fd must close");
    require(ocra_secret_record_parse(data, (size_t)length, record) == 0,
            "client profile must parse");
    (void)memset(data, 0, sizeof(data));
}

static int records_match_for_test(const struct ocra_secret_record *left,
                                  const struct ocra_secret_record *right)
{
    return memcmp(left, right, sizeof(*left)) == 0;
}

static int rate_state_exists(struct enroll_fixture *fixture,
                             const char *key_id)
{
    char name[192];
    struct stat status;

    require(snprintf(name, sizeof(name), "%s-%s-%s.state", TEST_UID_TEXT,
                     TEST_SERVICE, key_id) > 0,
            "rate state name must format");
    if (fstatat(fixture->rate_fd, name, &status, AT_SYMLINK_NOFOLLOW) == 0) {
        return 1;
    }
    require(errno == ENOENT, "rate state lookup must be determinate");
    return 0;
}

static int server_record_exists(struct enroll_fixture *fixture,
                                const char *service)
{
    char file_name[96];
    struct stat status;
    int users_fd;
    int uid_fd;
    int exists = 0;

    users_fd = openat(fixture->server_fd, "users",
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (users_fd < 0) {
        return 0;
    }
    uid_fd = openat(users_fd, TEST_UID_TEXT,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    (void)close(users_fd);
    if (uid_fd < 0) {
        return 0;
    }
    require(snprintf(file_name, sizeof(file_name), "%s.conf", service) > 0,
            "server record name must format");
    if (fstatat(uid_fd, file_name, &status, AT_SYMLINK_NOFOLLOW) == 0) {
        exists = 1;
    } else {
        require(errno == ENOENT, "server record lookup must be determinate");
    }
    require(close(uid_fd) == 0, "server uid directory must close");
    return exists;
}

static int transaction_journal_exists(struct enroll_fixture *fixture);
static int transaction_journal_has_phase(struct enroll_fixture *fixture,
                                         const char *phase);

static void require_pair_absent(struct enroll_fixture *fixture)
{
    struct stat status;

    require(!server_record_exists(fixture, TEST_SERVICE),
            "failed add must not leave a server record");
    require(fstatat(AT_FDCWD, fixture->profile_path, &status,
                    AT_SYMLINK_NOFOLLOW) != 0 &&
                errno == ENOENT,
            "failed add must not leave a client profile");
    require(!transaction_journal_exists(fixture),
            "returned add failure must not leave a recovery journal");
}

static void test_add_creates_compatible_server_and_client_records(void)
{
    struct enroll_fixture fixture;
    struct ocra_secret_record server_record;
    struct ocra_secret_record client_record;
    unsigned char profile[OCRA_SECRET_FILE_MAX + 1U];
    char *arguments[] = {"ocra-enroll", "add", "--user", TEST_USER,
                         "--service", TEST_SERVICE, "--client-profile", NULL};
    FILE *input = tmpfile();
    FILE *output = tmpfile();
    FILE *error = tmpfile();
    char *stdout_text;
    char *stderr_text;
    size_t stdout_length;
    size_t stderr_length;
    int profile_fd;
    ssize_t profile_length;
    struct stat profile_status;

    fixture_create(&fixture);
    arguments[7] = fixture.profile_path;
    require(input != NULL && output != NULL && error != NULL,
            "test streams must be created");
    require(ocra_enroll_run_at_for_tests(8, arguments, input, output, error,
                                         fixture.server_fd,
                                         fixture.rate_fd) == 0,
            "valid add must succeed");
    require(random_call == 3U,
            "valid add must consume secret, key-id and independent txid randomness");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &server_record) == 0,
            "server record must load through the production parser");
    profile_fd = open(fixture.profile_path,
                      O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    require(profile_fd >= 0, "client profile must open");
    require(fstat(profile_fd, &profile_status) == 0 &&
                S_ISREG(profile_status.st_mode) &&
                (profile_status.st_mode & 07777) == 0600 &&
                profile_status.st_uid == (uid_t)1000 &&
                profile_status.st_gid == getegid(),
            "client profile must have exact mode and resolved ownership");
    profile_length = read(profile_fd, profile, OCRA_SECRET_FILE_MAX + 1U);
    require(profile_length > 0 &&
                (size_t)profile_length <= OCRA_SECRET_FILE_MAX,
            "client profile must have a bounded body");
    require(close(profile_fd) == 0, "client profile must close");
    require(ocra_secret_record_parse(profile, (size_t)profile_length,
                                     &client_record) == 0,
            "client profile must use the exact compatible format");
    require(memcmp(server_record.secret, client_record.secret,
                   OCRA_SECRET_BYTES) == 0,
            "server and client secrets must match");
    require(strcmp(server_record.key_id, client_record.key_id) == 0,
            "server and client key identifiers must match");
    require(strcmp(server_record.key_id, "8081828384858687") == 0,
            "key identifier must encode exactly eight random bytes");
    stdout_text = read_stream_binary(output, &stdout_length);
    stderr_text = read_stream_binary(error, &stderr_length);
    require(strstr(stdout_text,
                   "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ") ==
                    NULL &&
                strstr(stderr_text,
                       "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ") ==
                    NULL &&
                !buffer_contains(stdout_text, stdout_length,
                                 server_record.secret, OCRA_SECRET_BYTES) &&
                !buffer_contains(stderr_text, stderr_length,
                                 server_record.secret, OCRA_SECRET_BYTES) &&
                strstr(stdout_text, "secret=") == NULL &&
                strstr(stderr_text, "secret=") == NULL &&
                strstr(stdout_text, server_record.key_id) == NULL &&
                strstr(stderr_text, server_record.key_id) == NULL,
            "add output must not disclose secret or key material");
    free(stderr_text);
    free(stdout_text);
    ocra_secret_record_clear(&client_record);
    ocra_secret_record_clear(&server_record);
    (void)memset(profile, 0, sizeof(profile));
    require(fclose(input) == 0 && fclose(output) == 0 && fclose(error) == 0,
            "test streams must close");
    fixture_destroy(&fixture);
}

static void test_stream_capture_preserves_embedded_nul_length(void)
{
    unsigned char bytes[OCRA_SECRET_BYTES];
    char *captured;
    size_t captured_length = 0U;
    FILE *stream;
    size_t index;

    for (index = 0U; index < sizeof(bytes); ++index) {
        bytes[index] = (unsigned char)index;
    }
    stream = tmpfile();
    require(stream != NULL &&
                fwrite(bytes, 1U, sizeof(bytes), stream) == sizeof(bytes),
            "binary disclosure fixture must be written completely");
    captured = read_stream_binary(stream, &captured_length);
    require(captured_length == sizeof(bytes) &&
                memcmp(captured, bytes, sizeof(bytes)) == 0,
            "stream capture length must include bytes after embedded NUL");
    free(captured);
    require(fclose(stream) == 0,
            "binary disclosure fixture stream must close");
    (void)memset(bytes, 0, sizeof(bytes));
}

static void test_admin_lock_cleanup_attempts_every_step_after_failures(void)
{
    static const enum ocra_enroll_fault_operation faults[] = {
        OCRA_ENROLL_FAULT_ADMIN_FSYNC,
        OCRA_ENROLL_FAULT_ADMIN_UNLOCK,
    };
    size_t index;

    for (index = 0U; index < sizeof(faults) / sizeof(faults[0]); ++index) {
        struct enroll_fixture fixture;
        unsigned int fsync_calls = 0U;
        unsigned int unlock_calls = 0U;
        unsigned int close_calls = 0U;

        fixture_create(&fixture);
        require(run_add(&fixture) == 0,
                "credential for administrative cleanup fault must add");
        ocra_enroll_reset_lock_cleanup_counts_for_tests();
        ocra_enroll_set_fault_for_tests(faults[index], 1U);
        require(run_server_only_command(&fixture, "inspect", TEST_SERVICE,
                                        NULL, NULL) != 0,
                "administrative cleanup fault must fail the invocation");
        ocra_enroll_get_lock_cleanup_counts_for_tests(
            &fsync_calls, &unlock_calls, &close_calls);
        require(fsync_calls == 1U && unlock_calls == 1U && close_calls == 1U,
                "fsync, unlock and close must all run despite earlier failure");
        ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
        require(run_server_only_command(&fixture, "inspect", TEST_SERVICE,
                                        NULL, NULL) == 0,
                "close must release lock even when explicit unlock fails");
        fixture_destroy(&fixture);
    }
}

static void test_add_recovers_crashes_inside_each_staged_write(void)
{
    unsigned int occurrence;

    for (occurrence = 1U; occurrence <= 3U; ++occurrence) {
        struct enroll_fixture fixture;
        struct ocra_secret_record server_record;
        struct ocra_secret_record client_record;

        fixture_create(&fixture);
        ocra_enroll_set_fault_for_tests(
            OCRA_ENROLL_FAULT_INTERRUPT_STAGE_WRITE, occurrence);
        require(run_add(&fixture) != 0,
                "stage-write process interruption must stop add");
        ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
        require(run_add(&fixture) == 0,
                "next add must recover bootstrap/server/client partial stage");
        require(ocra_secret_store_load_at(
                    fixture.server_fd, TEST_UID_TEXT, TEST_SERVICE,
                    &server_record) == 0,
                "recovered add server record must load");
        load_client_record(&fixture, &client_record);
        require(records_match_for_test(&server_record, &client_record) &&
                    !transaction_journal_exists(&fixture),
                "stage-write recovery must converge to one committed pair");
        ocra_secret_record_clear(&client_record);
        ocra_secret_record_clear(&server_record);
        fixture_destroy(&fixture);
    }
}

static void test_add_preserves_precreated_client_transaction_name(void)
{
    struct enroll_fixture fixture;
    static const char body[] = "attacker-owned\n";
    char transaction_path[256];
    struct stat before;
    struct stat after;
    int fd;

    fixture_create(&fixture);
    require(snprintf(transaction_path, sizeof(transaction_path),
                     "%s/.ocra-admin-9091929394959697",
                     fixture.client_path) > 0,
            "deterministic client transaction path must format");
    fd = open(transaction_path,
              O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    require(fd >= 0 &&
                write(fd, body, sizeof(body) - 1U) ==
                    (ssize_t)(sizeof(body) - 1U) &&
                close(fd) == 0 &&
                lstat(transaction_path, &before) == 0,
            "attacker transaction-name entry must be created");
    require(run_add(&fixture) != 0,
            "precreated transaction-name entry must fail closed");
    require(lstat(transaction_path, &after) == 0 &&
                before.st_dev == after.st_dev &&
                before.st_ino == after.st_ino &&
                before.st_size == after.st_size &&
                !server_record_exists(&fixture, TEST_SERVICE),
            "failed add must preserve the precreated entry and server state");
    fixture_destroy(&fixture);
}

static void test_add_preserves_precreated_transaction_symlink_and_hardlink(void)
{
    unsigned int kind;

    for (kind = 0U; kind < 2U; ++kind) {
        struct enroll_fixture fixture;
        static const char body[] = "attacker-referent\n";
        char transaction_path[256];
        char sentinel_path[256];
        struct stat before;
        struct stat after;
        struct stat sentinel_before;
        struct stat sentinel_after;
        int fd;

        fixture_create(&fixture);
        require(snprintf(transaction_path, sizeof(transaction_path),
                         "%s/.ocra-admin-9091929394959697",
                         fixture.client_path) > 0 &&
                    snprintf(sentinel_path, sizeof(sentinel_path),
                             "%s/attacker-referent", fixture.root_path) > 0,
                "adversarial transaction paths must format");
        fd = open(sentinel_path,
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        require(fd >= 0 &&
                    write(fd, body, sizeof(body) - 1U) ==
                        (ssize_t)(sizeof(body) - 1U) &&
                    close(fd) == 0,
                "adversarial transaction referent must be created");
        require((kind == 0U ? symlink(sentinel_path, transaction_path)
                            : link(sentinel_path, transaction_path)) == 0 &&
                    lstat(transaction_path, &before) == 0 &&
                    stat(sentinel_path, &sentinel_before) == 0,
                "adversarial transaction entry must be installed");
        require(run_add(&fixture) != 0,
                "unsafe transaction entry must fail closed");
        require(lstat(transaction_path, &after) == 0 &&
                    stat(sentinel_path, &sentinel_after) == 0 &&
                    before.st_dev == after.st_dev &&
                    before.st_ino == after.st_ino &&
                    sentinel_before.st_dev == sentinel_after.st_dev &&
                    sentinel_before.st_ino == sentinel_after.st_ino &&
                    sentinel_before.st_size == sentinel_after.st_size &&
                    !server_record_exists(&fixture, TEST_SERVICE),
                "unsafe transaction entry and referent must remain untouched");
        fixture_destroy(&fixture);
    }
}

static void test_owner_mismatch_rejects_user_owned_transaction_directory(void)
{
    struct enroll_fixture fixture;
    char transaction_path[256];
    struct stat before;
    struct stat after;

    if (getenv("OCRA_TEST_REQUIRE_ENROLL_OWNER_MISMATCH") == NULL) {
        return;
    }
    require(geteuid() == (uid_t)0 && geteuid() != (uid_t)1000,
            "owner-mismatch harness must execute as administrative root");
    fixture_create(&fixture);
    require(snprintf(transaction_path, sizeof(transaction_path),
                     "%s/.ocra-admin-9091929394959697",
                     fixture.client_path) > 0 &&
                mkdir(transaction_path, 0700) == 0 &&
                chown(transaction_path, (uid_t)1000, getegid()) == 0 &&
                lstat(transaction_path, &before) == 0 &&
                before.st_uid == (uid_t)1000,
            "user-owned transaction directory must be precreated");
    require(run_add(&fixture) != 0,
            "user-owned transaction directory must fail closed");
    require(lstat(transaction_path, &after) == 0 &&
                before.st_dev == after.st_dev &&
                before.st_ino == after.st_ino &&
                after.st_uid == (uid_t)1000 &&
                !server_record_exists(&fixture, TEST_SERVICE) &&
                transaction_journal_exists(&fixture),
            "owner-mismatch rejection must preserve attacker entry and intent");
    fixture_destroy(&fixture);
}

static void test_rotation_recovers_partial_restore_stages(void)
{
    static const struct {
        enum ocra_enroll_fault_operation fault;
        unsigned int first_occurrence;
        unsigned int last_occurrence;
    } cases[] = {
        {OCRA_ENROLL_FAULT_INTERRUPT_STAGE_WRITE, 8U, 8U},
        {OCRA_ENROLL_FAULT_INTERRUPT_STAGE_FSYNC, 15U, 16U},
    };
    static const char invalid_response[] = "00000000\n";
    size_t test_case;

    for (test_case = 0U; test_case < sizeof(cases) / sizeof(cases[0]);
         ++test_case) {
        unsigned int occurrence;

        for (occurrence = cases[test_case].first_occurrence;
             occurrence <= cases[test_case].last_occurrence; ++occurrence) {
            struct enroll_fixture fixture;
            struct ocra_secret_record old_record;
            struct ocra_secret_record server_record;
            struct ocra_secret_record client_record;

            fixture_create(&fixture);
            require(run_add(&fixture) == 0 &&
                        ocra_secret_store_load_at(
                            fixture.server_fd, TEST_UID_TEXT, TEST_SERVICE,
                            &old_record) == 0,
                    "partial restore fixture must start with an old pair");
            ocra_enroll_set_fault_for_tests(cases[test_case].fault,
                                            occurrence);
            require(run_rotate(&fixture, invalid_response, NULL, NULL) != 0 &&
                        transaction_journal_has_phase(&fixture, "prepared"),
                    "restore stage interruption must preserve recovery intent");
            ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
            require(run_server_only_command(&fixture, "inspect", TEST_SERVICE,
                                            NULL, NULL) == 0 &&
                        ocra_secret_store_load_at(
                            fixture.server_fd, TEST_UID_TEXT, TEST_SERVICE,
                            &server_record) == 0,
                    "next invocation must recover a partial restore stage");
            load_client_record(&fixture, &client_record);
            require(records_match_for_test(&old_record, &server_record) &&
                        records_match_for_test(&old_record, &client_record) &&
                        !transaction_journal_exists(&fixture),
                    "partial restore recovery must converge to the old pair");
            ocra_secret_record_clear(&client_record);
            ocra_secret_record_clear(&server_record);
            ocra_secret_record_clear(&old_record);
            fixture_destroy(&fixture);
        }
    }
}

static void test_revoke_recovers_partial_backup_stage(void)
{
    static const struct {
        enum ocra_enroll_fault_operation fault;
        unsigned int first_occurrence;
        unsigned int last_occurrence;
    } cases[] = {
        {OCRA_ENROLL_FAULT_INTERRUPT_STAGE_WRITE, 2U, 2U},
        {OCRA_ENROLL_FAULT_INTERRUPT_STAGE_FSYNC, 3U, 4U},
    };
    size_t test_case;

    for (test_case = 0U; test_case < sizeof(cases) / sizeof(cases[0]);
         ++test_case) {
        unsigned int occurrence;

        for (occurrence = cases[test_case].first_occurrence;
             occurrence <= cases[test_case].last_occurrence; ++occurrence) {
            struct enroll_fixture fixture;
            struct ocra_secret_record old_record;
            struct ocra_secret_record current;

            fixture_create(&fixture);
            require(run_add(&fixture) == 0 &&
                        ocra_secret_store_load_at(
                            fixture.server_fd, TEST_UID_TEXT, TEST_SERVICE,
                            &old_record) == 0,
                    "partial revoke fixture must start with a credential");
            ocra_enroll_set_fault_for_tests(cases[test_case].fault,
                                            occurrence);
            require(run_server_only_command(&fixture, "revoke", TEST_SERVICE,
                                            NULL, NULL) != 0 &&
                        transaction_journal_has_phase(&fixture, "preparing"),
                    "revoke backup interruption must preserve PREPARING intent");
            ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
            require(run_server_only_command(&fixture, "inspect", TEST_SERVICE,
                                            NULL, NULL) == 0 &&
                        ocra_secret_store_load_at(
                            fixture.server_fd, TEST_UID_TEXT, TEST_SERVICE,
                            &current) == 0 &&
                        records_match_for_test(&old_record, &current) &&
                        !transaction_journal_exists(&fixture),
                    "partial revoke backup recovery must preserve old state");
            ocra_secret_record_clear(&current);
            ocra_secret_record_clear(&old_record);
            fixture_destroy(&fixture);
        }
    }
}

static void test_cli_rejects_secret_options_relative_paths_and_random_failure(void)
{
    struct enroll_fixture fixture;
    char *secret_arguments[] = {
        "ocra-enroll", "add", "--user", TEST_USER, "--service",
        TEST_SERVICE, "--client-profile", NULL, "--secret", "FORBIDDEN"};
    char *relative_arguments[] = {"ocra-enroll", "add", "--user", TEST_USER,
                                  "--service", TEST_SERVICE,
                                  "--client-profile", "relative.conf"};
    FILE *input;
    FILE *output;
    FILE *error;

    fixture_create(&fixture);
    secret_arguments[7] = fixture.profile_path;
    input = tmpfile();
    output = tmpfile();
    error = tmpfile();
    require(input != NULL && output != NULL && error != NULL,
            "strict CLI streams must be created");
    require(ocra_enroll_run_at_for_tests(10, secret_arguments, input, output,
                                         error, fixture.server_fd,
                                         fixture.rate_fd) != 0,
            "CLI must never accept secret material as an option");
    require(ocra_enroll_run_at_for_tests(8, relative_arguments, input, output,
                                         error, fixture.server_fd,
                                         fixture.rate_fd) != 0,
            "client profile must be an explicit absolute path");
    require_pair_absent(&fixture);
    ocra_enroll_set_random_provider_for_tests(failing_random);
    require(run_add(&fixture) != 0,
            "getrandom failure must deny enrollment");
    require_pair_absent(&fixture);
    require(fclose(input) == 0 && fclose(output) == 0 && fclose(error) == 0,
            "strict CLI streams must close");
    fixture_destroy(&fixture);
}

static void test_add_rejects_unknown_user_invalid_service_and_non_root(void)
{
    struct enroll_fixture fixture;
    char *arguments[] = {"ocra-enroll", "add", "--user", TEST_USER,
                         "--service", TEST_SERVICE, "--client-profile", NULL};
    FILE *input;
    FILE *output;
    FILE *error;

    fixture_create(&fixture);
    arguments[7] = fixture.profile_path;
    input = tmpfile();
    output = tmpfile();
    error = tmpfile();
    require(input != NULL && output != NULL && error != NULL,
            "validation streams must be created");
    ocra_enroll_set_user_provider_for_tests(resolve_no_user);
    require(ocra_enroll_run_at_for_tests(8, arguments, input, output, error,
                                         fixture.server_fd,
                                         fixture.rate_fd) != 0,
            "unknown user must be rejected");
    require_pair_absent(&fixture);
    ocra_enroll_set_user_provider_for_tests(resolve_test_user);
    arguments[5] = "sudo/../../login";
    require(ocra_enroll_run_at_for_tests(8, arguments, input, output, error,
                                         fixture.server_fd,
                                         fixture.rate_fd) != 0,
            "invalid service must be rejected");
    require_pair_absent(&fixture);
    arguments[5] = TEST_SERVICE;
    ocra_enroll_set_euid_for_tests((uid_t)1000);
    require(ocra_enroll_run_at_for_tests(8, arguments, input, output, error,
                                         fixture.server_fd,
                                         fixture.rate_fd) != 0,
            "non-root caller must be rejected");
    require_pair_absent(&fixture);
    require(random_call == 0U,
            "rejected validation must not generate secret material");
    require(fclose(input) == 0 && fclose(output) == 0 && fclose(error) == 0,
            "validation streams must close");
    fixture_destroy(&fixture);
}

static void test_add_rejects_collision_without_changing_existing_pair(void)
{
    struct enroll_fixture fixture;
    struct ocra_secret_record before;
    struct ocra_secret_record after;

    fixture_create(&fixture);
    require(run_add(&fixture) == 0, "fixture add must succeed");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &before) == 0,
            "existing server record must load");
    require(run_add(&fixture) != 0,
            "add collision without overwrite must be rejected");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &after) == 0,
            "server record must remain loadable after collision");
    require(memcmp(&before, &after, sizeof(before)) == 0,
            "collision must preserve the existing credential");
    require(random_call == 3U,
            "collision must fail before generating another credential");
    ocra_secret_record_clear(&after);
    ocra_secret_record_clear(&before);
    fixture_destroy(&fixture);
}

static void test_add_rejects_symlink_target_without_touching_referent(void)
{
    static const char sentinel_body[] = "do-not-touch\n";
    struct enroll_fixture fixture;
    char sentinel_path[256];
    char buffer[sizeof(sentinel_body)];
    int sentinel_fd;

    fixture_create(&fixture);
    require(snprintf(sentinel_path, sizeof(sentinel_path), "%s/sentinel",
                     fixture.root_path) > 0,
            "sentinel path must format");
    sentinel_fd = open(sentinel_path,
                       O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    require(sentinel_fd >= 0, "sentinel must be created");
    require(write(sentinel_fd, sentinel_body, sizeof(sentinel_body) - 1U) ==
                (ssize_t)(sizeof(sentinel_body) - 1U),
            "sentinel must be populated");
    require(close(sentinel_fd) == 0, "sentinel writer must close");
    require(symlink(sentinel_path, fixture.profile_path) == 0,
            "profile symlink must be created");
    require(run_add(&fixture) != 0, "symlink profile must be rejected");
    require(!server_record_exists(&fixture, TEST_SERVICE),
            "symlink rejection must not create server state");
    sentinel_fd = open(sentinel_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    require(sentinel_fd >= 0, "sentinel must reopen");
    (void)memset(buffer, 0, sizeof(buffer));
    require(read(sentinel_fd, buffer, sizeof(buffer)) ==
                (ssize_t)(sizeof(sentinel_body) - 1U),
            "sentinel must remain readable");
    require(memcmp(buffer, sentinel_body, sizeof(sentinel_body) - 1U) == 0,
            "symlink referent must remain unchanged");
    require(close(sentinel_fd) == 0, "sentinel reader must close");
    fixture_destroy(&fixture);
}

static void test_add_rolls_back_each_persistence_boundary(void)
{
    static const struct {
        enum ocra_enroll_fault_operation operation;
        unsigned int occurrence;
        const char *message;
    } faults[] = {
        {OCRA_ENROLL_FAULT_WRITE_PARTIAL, 1U,
         "partial server write must roll back"},
        {OCRA_ENROLL_FAULT_WRITE_PARTIAL, 2U,
         "partial client write must roll back"},
        {OCRA_ENROLL_FAULT_WRITE_PARTIAL, 3U,
         "partial prepared-journal write must roll back"},
        {OCRA_ENROLL_FAULT_FSYNC_FILE, 1U,
         "server file fsync failure must roll back"},
        {OCRA_ENROLL_FAULT_FSYNC_FILE, 2U,
         "client file fsync failure must roll back"},
        {OCRA_ENROLL_FAULT_FSYNC_FILE, 3U,
         "prepared-journal fsync failure must roll back"},
        {OCRA_ENROLL_FAULT_RENAME, 1U,
         "prepared-journal rename failure must roll back"},
        {OCRA_ENROLL_FAULT_FSYNC_DIRECTORY, 1U,
         "prepared-journal dir fsync failure must roll back"},
        {OCRA_ENROLL_FAULT_RENAME, 2U,
         "failure before server rename must roll back"},
        {OCRA_ENROLL_FAULT_FSYNC_DIRECTORY, 2U,
         "failure after server rename must roll back"},
        {OCRA_ENROLL_FAULT_RENAME, 3U,
         "failure before client rename must roll back"},
        {OCRA_ENROLL_FAULT_FSYNC_DIRECTORY, 3U,
         "failure after client rename must roll back"},
        {OCRA_ENROLL_FAULT_WRITE_PARTIAL, 4U,
         "partial committing-journal write must roll back"},
        {OCRA_ENROLL_FAULT_FSYNC_FILE, 4U,
         "committing-journal fsync failure must roll back"},
        {OCRA_ENROLL_FAULT_RENAME, 4U,
         "committing-journal rename failure must roll back"},
        {OCRA_ENROLL_FAULT_FSYNC_DIRECTORY, 4U,
         "committing-journal dir fsync failure must roll back"},
    };
    size_t index;

    for (index = 0U; index < sizeof(faults) / sizeof(faults[0]); ++index) {
        struct enroll_fixture fixture;

        fixture_create(&fixture);
        ocra_enroll_set_fault_for_tests(faults[index].operation,
                                        faults[index].occurrence);
        require(run_add(&fixture) != 0, faults[index].message);
        require_pair_absent(&fixture);
        fixture_destroy(&fixture);
    }
}

static void test_rotate_confirms_externally_then_retires_old_credential(void)
{
    struct enroll_fixture fixture;
    struct ocra_secret_record old_record;
    struct ocra_secret_record server_record;
    struct ocra_secret_record client_record;
    unsigned char new_secret[OCRA_SECRET_BYTES];
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];
    char response[OCRA_RESPONSE_CAPACITY + 1U];
    char reserved[OCRA_CHALLENGE_DIGITS + 1U];
    char *stdout_text = NULL;
    char *stderr_text = NULL;
    size_t stdout_length = 0U;
    size_t stderr_length = 0U;
    size_t index;

    fixture_create(&fixture);
    require(run_add(&fixture) == 0, "credential to rotate must be enrolled");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &old_record) == 0,
            "old credential must load");
    require(ocra_rate_limit_reserve_at(fixture.rate_fd, TEST_UID_TEXT,
                                       TEST_SERVICE, old_record.key_id,
                                       reserved) == 0,
            "old key must have associated rate state");
    require(rate_state_exists(&fixture, old_record.key_id),
            "old rate state must exist before rotation");
    for (index = 0U; index < sizeof(new_secret); ++index) {
        new_secret[index] = (unsigned char)(0x40U + index);
    }
    (void)strcpy(challenge, "0000000001");
    require(ocra_compute_response(new_secret, sizeof(new_secret), challenge,
                                  OCRA_CHALLENGE_DIGITS, response,
                                  OCRA_RESPONSE_CAPACITY) == 0,
            "independent client response must compute");
    require(strcat(response, "\n") != NULL,
            "confirmation response must include line ending");
    require(run_rotate_captured(&fixture, response, &stdout_text,
                                &stdout_length, &stderr_text,
                                &stderr_length) == 0,
            "rotation with independently produced response must succeed");
    require(strstr(stdout_text, "0000000001") != NULL,
            "rotation must present the independent confirmation challenge");
    require(strstr(stdout_text, response) == NULL &&
                strstr(stderr_text, response) == NULL,
            "rotation must never echo the confirmation response");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &server_record) == 0,
            "rotated server record must load");
    load_client_record(&fixture, &client_record);
    require(strcmp(server_record.key_id, old_record.key_id) != 0,
            "rotation must install a distinct key identifier");
    require(strcmp(server_record.key_id, "a0a1a2a3a4a5a6a7") == 0,
            "rotated key identifier must use fresh random bytes");
    require(memcmp(&server_record, &client_record, sizeof(server_record)) == 0,
            "rotated server and client records must match");
    require(strstr(stdout_text,
                   "IBAUEQ2EIVDEOSCJJJFUYTKOJ5IFCUSTKRKVMV2YLFNFWXC5LZPQ") ==
                    NULL &&
                strstr(stderr_text,
                       "IBAUEQ2EIVDEOSCJJJFUYTKOJ5IFCUSTKRKVMV2YLFNFWXC5LZPQ") ==
                    NULL &&
                !buffer_contains(stdout_text, stdout_length,
                                 server_record.secret, OCRA_SECRET_BYTES) &&
                !buffer_contains(stderr_text, stderr_length,
                                 server_record.secret, OCRA_SECRET_BYTES),
            "rotation output must hide encoded and decoded secret bytes");
    require(!rate_state_exists(&fixture, old_record.key_id),
            "successful rotation must remove old key rate state");
    require(!rate_state_exists(&fixture, server_record.key_id),
            "new key must start without inherited rate state");
    free(stderr_text);
    free(stdout_text);
    (void)memset(response, 0, sizeof(response));
    (void)memset(new_secret, 0, sizeof(new_secret));
    ocra_secret_record_clear(&client_record);
    ocra_secret_record_clear(&server_record);
    ocra_secret_record_clear(&old_record);
    fixture_destroy(&fixture);
}

static void test_failed_rotation_confirmation_restores_old_pair(void)
{
    struct enroll_fixture fixture;
    struct ocra_secret_record old_record;
    struct ocra_secret_record server_record;
    struct ocra_secret_record client_record;

    fixture_create(&fixture);
    require(run_add(&fixture) == 0, "credential to reject must be enrolled");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &old_record) == 0,
            "old credential must load before failed confirmation");
    require(run_rotate(&fixture, "00000000\n", NULL, NULL) != 0,
            "incorrect independent response must reject rotation");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &server_record) == 0,
            "server credential must survive failed confirmation");
    load_client_record(&fixture, &client_record);
    require(memcmp(&old_record, &server_record, sizeof(old_record)) == 0 &&
                memcmp(&old_record, &client_record, sizeof(old_record)) == 0,
            "failed confirmation must restore the complete old pair");
    ocra_secret_record_clear(&client_record);
    ocra_secret_record_clear(&server_record);
    ocra_secret_record_clear(&old_record);
    fixture_destroy(&fixture);
}

static void test_inspect_exposes_only_non_sensitive_metadata(void)
{
    struct enroll_fixture fixture;
    char *stdout_text = NULL;
    char *stderr_text = NULL;

    fixture_create(&fixture);
    require(run_add(&fixture) == 0, "credential to inspect must be enrolled");
    require(run_server_only_command(&fixture, "inspect", TEST_SERVICE,
                                    &stdout_text, &stderr_text) == 0,
            "inspect of enrolled scope must succeed");
    require(strstr(stdout_text, "uid=" TEST_UID_TEXT) != NULL &&
                strstr(stdout_text, "service=" TEST_SERVICE) != NULL &&
                strstr(stdout_text, "enabled=yes") != NULL &&
                strstr(stdout_text, "key_id=8081828384858687") != NULL,
            "inspect must provide only useful credential metadata");
    require(strstr(stdout_text, "secret=") == NULL &&
                strstr(stdout_text, "suite=") == NULL &&
                strstr(stderr_text, "secret=") == NULL,
            "inspect must not disclose secret-bearing fields");
    free(stderr_text);
    free(stdout_text);
    fixture_destroy(&fixture);
}

static void test_revoke_removes_only_requested_scope_and_old_rate_state(void)
{
    struct enroll_fixture fixture;
    struct ocra_secret_record sudo_record;
    struct ocra_secret_record login_record;
    char login_profile[256];
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];
    char *stdout_text = NULL;
    char *stderr_text = NULL;
    struct stat profile_status;

    fixture_create(&fixture);
    require(run_add(&fixture) == 0, "sudo credential must be enrolled");
    require(snprintf(login_profile, sizeof(login_profile), "%s/alice-login.conf",
                     fixture.client_path) > 0,
            "independent profile path must format");
    require(run_add_scope(&fixture, "login", login_profile) == 0,
            "independent login credential must be enrolled");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &sudo_record) == 0 &&
                ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                          "login", &login_record) == 0,
            "both independent server scopes must load");
    require(ocra_rate_limit_reserve_at(fixture.rate_fd, TEST_UID_TEXT,
                                       TEST_SERVICE, sudo_record.key_id,
                                       challenge) == 0,
            "revoked scope must have rate state");
    require(run_server_only_command(&fixture, "revoke", TEST_SERVICE,
                                    &stdout_text, &stderr_text) == 0,
            "revoke of enrolled scope must succeed");
    require(!server_record_exists(&fixture, TEST_SERVICE),
            "revoke must remove requested server credential");
    require(server_record_exists(&fixture, "login"),
            "revoke must preserve other service credential");
    require(!rate_state_exists(&fixture, sudo_record.key_id),
            "revoke must remove requested key rate state");
    require(fstatat(AT_FDCWD, fixture.profile_path, &profile_status,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
                S_ISREG(profile_status.st_mode),
            "revoke without a client path must not touch client profile");
    require(strstr(stdout_text, "revoke") != NULL &&
                strstr(stdout_text, "uid=" TEST_UID_TEXT) != NULL &&
                strstr(stdout_text, "service=" TEST_SERVICE) != NULL &&
                strstr(stdout_text, sudo_record.key_id) == NULL &&
                strstr(stderr_text, sudo_record.key_id) == NULL &&
                strstr(stdout_text, challenge) == NULL &&
                strstr(stderr_text, challenge) == NULL,
            "revoke log must contain only operation UID and service");
    free(stderr_text);
    free(stdout_text);
    ocra_secret_record_clear(&login_record);
    ocra_secret_record_clear(&sudo_record);
    fixture_destroy(&fixture);
}

static void compute_second_credential_response(char response[10U])
{
    unsigned char new_secret[OCRA_SECRET_BYTES];
    size_t index;

    for (index = 0U; index < sizeof(new_secret); ++index) {
        new_secret[index] = (unsigned char)(0x40U + index);
    }
    require(ocra_compute_response(new_secret, sizeof(new_secret),
                                  "0000000001", OCRA_CHALLENGE_DIGITS,
                                  response, OCRA_RESPONSE_CAPACITY) == 0,
            "second credential confirmation response must compute");
    response[OCRA_RESPONSE_DIGITS] = '\n';
    response[OCRA_RESPONSE_DIGITS + 1U] = '\0';
    (void)memset(new_secret, 0, sizeof(new_secret));
}

static void test_rate_cleanup_failure_rolls_forward_committing_operations(void)
{
    struct enroll_fixture fixture;
    struct ocra_secret_record old_record;
    struct ocra_secret_record current;
    char response[10U];
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];

    fixture_create(&fixture);
    require(run_add(&fixture) == 0, "credential for cleanup failure must add");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &old_record) == 0,
            "old cleanup-failure record must load");
    require(ocra_rate_limit_reserve_at(fixture.rate_fd, TEST_UID_TEXT,
                                       TEST_SERVICE, old_record.key_id,
                                       challenge) == 0,
            "old cleanup-failure state must exist");
    compute_second_credential_response(response);
    ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_RATE_CLEANUP, 1U);
    require(run_rotate(&fixture, response, NULL, NULL) != 0,
            "rate cleanup failure must reject rotation");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &current) == 0 &&
                !records_match_for_test(&old_record, &current),
            "COMMITTING rotation recovery must keep new server credential");
    load_client_record(&fixture, &current);
    require(!records_match_for_test(&old_record, &current) &&
                !rate_state_exists(&fixture, old_record.key_id) &&
                !transaction_journal_exists(&fixture),
            "COMMITTING rotation recovery must finish client and cleanup");
    require(ocra_rate_limit_reserve_at(fixture.rate_fd, TEST_UID_TEXT,
                                       TEST_SERVICE, current.key_id,
                                       challenge) == 0,
            "new credential rate state must exist before revoke fault");
    ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_RATE_CLEANUP, 1U);
    require(run_server_only_command(&fixture, "revoke", TEST_SERVICE, NULL,
                                    NULL) != 0,
            "rate cleanup failure must reject revoke");
    require(!server_record_exists(&fixture, TEST_SERVICE) &&
                !rate_state_exists(&fixture, current.key_id) &&
                !transaction_journal_exists(&fixture),
            "COMMITTING revoke recovery must finish irreversible cleanup");
    ocra_secret_record_clear(&current);
    ocra_secret_record_clear(&old_record);
    (void)memset(response, 0, sizeof(response));
    fixture_destroy(&fixture);
}

static void test_revoke_rejects_symlink_rate_state_without_touching_referent(void)
{
    static const char body[] = "rate-sentinel\n";
    struct enroll_fixture fixture;
    struct ocra_secret_record record;
    char state_name[192];
    char sentinel_path[256];
    char readback[sizeof(body)];
    int fd;

    fixture_create(&fixture);
    require(run_add(&fixture) == 0, "credential for unsafe state must add");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &record) == 0,
            "unsafe-state credential must load");
    require(snprintf(sentinel_path, sizeof(sentinel_path), "%s/rate-target",
                     fixture.root_path) > 0 &&
                snprintf(state_name, sizeof(state_name), "%s-%s-%s.state",
                         TEST_UID_TEXT, TEST_SERVICE, record.key_id) > 0,
            "unsafe rate paths must format");
    fd = open(sentinel_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    require(fd >= 0 && write(fd, body, sizeof(body) - 1U) ==
                           (ssize_t)(sizeof(body) - 1U) &&
                close(fd) == 0,
            "rate sentinel must be written");
    require(symlinkat(sentinel_path, fixture.rate_fd, state_name) == 0,
            "unsafe rate state symlink must be created");
    require(run_server_only_command(&fixture, "revoke", TEST_SERVICE, NULL,
                                    NULL) != 0,
            "unsafe rate state must deny revoke");
    require(!server_record_exists(&fixture, TEST_SERVICE) &&
                transaction_journal_exists(&fixture),
            "unsafe rate state after COMMITTING must fail closed with intent");
    fd = open(sentinel_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    require(fd >= 0 && read(fd, readback, sizeof(readback)) ==
                           (ssize_t)(sizeof(body) - 1U) &&
                close(fd) == 0 &&
                memcmp(readback, body, sizeof(body) - 1U) == 0,
            "unsafe rate symlink referent must remain unchanged");
    ocra_secret_record_clear(&record);
    fixture_destroy(&fixture);

}

static int transaction_journal_exists(struct enroll_fixture *fixture)
{
    struct stat status;
    int users_fd;
    int uid_fd;
    int exists;

    exists = fstatat(fixture->server_fd, "admin.txn", &status,
                     AT_SYMLINK_NOFOLLOW) == 0;
    if (exists) {
        return 1;
    }
    require(errno == ENOENT, "global journal lookup must be determinate");

    users_fd = openat(fixture->server_fd, "users",
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (users_fd < 0) {
        require(errno == ENOENT,
                "missing journal users directory must be determinate");
        return 0;
    }
    uid_fd = openat(users_fd, TEST_UID_TEXT,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (uid_fd < 0) {
        require(errno == ENOENT,
                "missing journal uid directory must be determinate");
        require(close(users_fd) == 0,
                "journal users directory must close when UID missing");
        return 0;
    }
    require(close(users_fd) == 0, "journal users directory must close");
    exists = fstatat(uid_fd, TEST_SERVICE ".txn", &status,
                     AT_SYMLINK_NOFOLLOW) == 0;
    if (!exists) {
        require(errno == ENOENT, "journal lookup must be determinate");
    }
    require(close(uid_fd) == 0, "journal uid directory must close");
    return exists;
}

static int transaction_journal_has_phase(struct enroll_fixture *fixture,
                                         const char *phase)
{
    char body[256U];
    char expected[64U];
    ssize_t length;
    int fd;

    (void)memset(body, 0, sizeof(body));
    require(snprintf(expected, sizeof(expected), "\nphase=%s\n", phase) > 0,
            "expected journal phase must format");
    fd = openat(fixture->server_fd, "admin.txn",
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        require(errno == ENOENT, "journal phase lookup must be determinate");
        return 0;
    }
    length = read(fd, body, sizeof(body) - 1U);
    require(length > 0 && close(fd) == 0,
            "journal prefix must read and close");
    return strstr(body, expected) != NULL;
}

static void test_next_rotation_recovers_interrupted_client_install(void)
{
    struct enroll_fixture fixture;
    struct ocra_secret_record old_record;
    struct ocra_secret_record current;
    char journal[4096U];
    char response[10U];
    char *stdout_text = NULL;
    char *stderr_text = NULL;
    size_t stdout_length = 0U;
    size_t stderr_length = 0U;
    ssize_t journal_length;
    int journal_fd;

    fixture_create(&fixture);
    require(run_add(&fixture) == 0,
            "credential for interruption recovery must add");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &old_record) == 0,
            "old interrupted credential must load");
    compute_second_credential_response(response);
    ocra_enroll_set_fault_for_tests(
        OCRA_ENROLL_FAULT_INTERRUPT_AFTER_CLIENT, 1U);
    require(run_rotate_captured(&fixture, response, &stdout_text,
                                &stdout_length, &stderr_text,
                                &stderr_length) != 0,
            "simulated process interruption must stop rotation");
    require(transaction_journal_exists(&fixture),
            "interrupted rotation must leave a durable recovery journal");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &current) == 0 &&
                memcmp(&old_record, &current, sizeof(old_record)) == 0,
            "server old credential must remain active during recovery window");
    load_client_record(&fixture, &current);
    require(memcmp(&old_record, &current, sizeof(old_record)) != 0,
            "interruption seam must prove client-new was already installed");
    (void)memset(journal, 0, sizeof(journal));
    journal_fd = openat(fixture.server_fd, "admin.txn",
                        O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    require(journal_fd >= 0,
            "interrupted rotation journal must open for disclosure audit");
    journal_length = read(journal_fd, journal, sizeof(journal));
    require(journal_length > 0 && (size_t)journal_length < sizeof(journal) &&
                close(journal_fd) == 0,
            "interrupted rotation journal must be bounded");
    require(strstr(journal,
                   "IBAUEQ2EIVDEOSCJJJFUYTKOJ5IFCUSTKRKVMV2YLFNFWXC5LZPQ") ==
                    NULL &&
                !buffer_contains(journal, (size_t)journal_length,
                                 current.secret, OCRA_SECRET_BYTES) &&
                strstr(stdout_text,
                       "IBAUEQ2EIVDEOSCJJJFUYTKOJ5IFCUSTKRKVMV2YLFNFWXC5LZPQ") ==
                    NULL &&
                strstr(stderr_text,
                       "IBAUEQ2EIVDEOSCJJJFUYTKOJ5IFCUSTKRKVMV2YLFNFWXC5LZPQ") ==
                    NULL &&
                !buffer_contains(stdout_text, stdout_length,
                                 current.secret, OCRA_SECRET_BYTES) &&
                !buffer_contains(stderr_text, stderr_length,
                                 current.secret, OCRA_SECRET_BYTES),
            "journal and failure output must hide encoded and raw secret");
    ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
    require(run_rotate(&fixture, "00000000\n", NULL, NULL) != 0,
            "next rotation may fail confirmation after performing recovery");
    require(!transaction_journal_exists(&fixture),
            "next invocation must consume the recovery journal");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &current) == 0 &&
                memcmp(&old_record, &current, sizeof(old_record)) == 0,
            "recovery must leave old server credential active");
    load_client_record(&fixture, &current);
    require(memcmp(&old_record, &current, sizeof(old_record)) == 0,
            "recovery plus failed retry must leave old client credential");
    free(stderr_text);
    free(stdout_text);
    (void)memset(journal, 0, sizeof(journal));
    (void)memset(response, 0, sizeof(response));
    ocra_secret_record_clear(&current);
    ocra_secret_record_clear(&old_record);
    fixture_destroy(&fixture);
}

static void test_add_overwrite_requires_flag_and_external_confirmation(void)
{
    struct enroll_fixture fixture;
    struct ocra_secret_record old_record;
    struct ocra_secret_record new_server;
    struct ocra_secret_record new_client;
    char response[10U];

    fixture_create(&fixture);
    require(run_add(&fixture) == 0, "overwrite baseline must add");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &old_record) == 0,
            "overwrite baseline record must load");
    require(run_add(&fixture) != 0,
            "collision must still fail without explicit overwrite flag");
    compute_second_credential_response(response);
    require(run_add_overwrite(&fixture, response) == 0,
            "explicit overwrite with external confirmation must succeed");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &new_server) == 0,
            "overwritten server credential must load");
    load_client_record(&fixture, &new_client);
    require(!records_match_for_test(&old_record, &new_server) &&
                records_match_for_test(&new_server, &new_client),
            "explicit overwrite must install one fresh matching pair");
    (void)memset(response, 0, sizeof(response));
    ocra_secret_record_clear(&new_client);
    ocra_secret_record_clear(&new_server);
    ocra_secret_record_clear(&old_record);
    fixture_destroy(&fixture);
}

static void test_next_rotation_rolls_forward_committing_transaction(void)
{
    struct enroll_fixture fixture;
    struct ocra_secret_record old_record;
    struct ocra_secret_record committed_record;
    struct ocra_secret_record current;
    char response[10U];
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];

    fixture_create(&fixture);
    require(run_add(&fixture) == 0,
            "credential for committing recovery must add");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &old_record) == 0,
            "old committing credential must load");
    require(ocra_rate_limit_reserve_at(fixture.rate_fd, TEST_UID_TEXT,
                                       TEST_SERVICE, old_record.key_id,
                                       challenge) == 0,
            "old committing state must exist");
    compute_second_credential_response(response);
    ocra_enroll_set_fault_for_tests(
        OCRA_ENROLL_FAULT_INTERRUPT_AFTER_COMMITTING, 1U);
    require(run_rotate(&fixture, response, NULL, NULL) != 0,
            "committing interruption must stop before cleanup");
    require(transaction_journal_exists(&fixture),
            "committing interruption must leave journal");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &committed_record) == 0 &&
                !records_match_for_test(&old_record, &committed_record),
            "COMMITTING boundary must already contain server-new");
    load_client_record(&fixture, &current);
    require(records_match_for_test(&committed_record, &current),
            "COMMITTING boundary must contain a matching new pair");
    ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
    require(run_rotate(&fixture, "00000000\n", NULL, NULL) != 0,
            "post-recovery retry may independently fail confirmation");
    require(!transaction_journal_exists(&fixture) &&
                !rate_state_exists(&fixture, old_record.key_id),
            "COMMITTING recovery must finish old state cleanup and journal");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &current) == 0 &&
                records_match_for_test(&committed_record, &current),
            "COMMITTING recovery must roll forward server-new");
    load_client_record(&fixture, &current);
    require(records_match_for_test(&committed_record, &current),
            "COMMITTING recovery must roll forward client-new");
    (void)memset(response, 0, sizeof(response));
    ocra_secret_record_clear(&current);
    ocra_secret_record_clear(&committed_record);
    ocra_secret_record_clear(&old_record);
    fixture_destroy(&fixture);
}

static void test_next_add_recovers_interrupted_server_install(void)
{
    struct enroll_fixture fixture;
    struct ocra_secret_record server_record;
    struct ocra_secret_record client_record;
    struct stat status;

    fixture_create(&fixture);
    ocra_enroll_set_fault_for_tests(
        OCRA_ENROLL_FAULT_INTERRUPT_AFTER_ADD_SERVER, 1U);
    require(run_add(&fixture) != 0,
            "simulated add interruption must stop after server install");
    require(transaction_journal_exists(&fixture) &&
                server_record_exists(&fixture, TEST_SERVICE),
            "interrupted add must journal its installed server half");
    require(fstatat(AT_FDCWD, fixture.profile_path, &status,
                    AT_SYMLINK_NOFOLLOW) != 0 &&
                errno == ENOENT,
            "interruption seam must occur before client install");
    ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
    require(run_add(&fixture) == 0,
            "next add must recover the partial pair before enrolling");
    require(!transaction_journal_exists(&fixture),
            "successful add recovery must consume journal");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &server_record) == 0,
            "recovered add server record must load");
    load_client_record(&fixture, &client_record);
    require(records_match_for_test(&server_record, &client_record) &&
                strcmp(server_record.key_id, "a0a1a2a3a4a5a6a7") == 0,
            "recovered add must install a wholly fresh matching pair");
    ocra_secret_record_clear(&client_record);
    ocra_secret_record_clear(&server_record);
    fixture_destroy(&fixture);
}

static void test_committing_recovery_rejects_mismatched_new_pair(void)
{
    struct enroll_fixture fixture;
    struct ocra_secret_record old_record;
    char response[10U];
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];
    char profile[OCRA_SECRET_FILE_MAX + 1U];
    char *secret;
    ssize_t length;
    int fd;

    fixture_create(&fixture);
    require(run_add(&fixture) == 0,
            "credential for mismatched recovery must add");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &old_record) == 0 &&
                ocra_rate_limit_reserve_at(
                    fixture.rate_fd, TEST_UID_TEXT, TEST_SERVICE,
                    old_record.key_id, challenge) == 0,
            "mismatched recovery must have old credential and rate state");
    compute_second_credential_response(response);
    ocra_enroll_set_fault_for_tests(
        OCRA_ENROLL_FAULT_INTERRUPT_AFTER_COMMITTING, 1U);
    require(run_rotate(&fixture, response, NULL, NULL) != 0 &&
                transaction_journal_exists(&fixture),
            "mismatched recovery setup must stop at COMMITTING");
    fd = open(fixture.profile_path,
              O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    require(fd >= 0, "committing client profile must open for corruption");
    length = read(fd, profile, OCRA_SECRET_FILE_MAX);
    require(length > 0 && (size_t)length < sizeof(profile),
            "committing client profile must read completely");
    profile[length] = '\0';
    secret = strstr(profile, "secret=");
    require(secret != NULL, "committing client secret field must exist");
    secret += strlen("secret=");
    *secret = *secret == 'A' ? 'B' : 'A';
    require(pwrite(fd, secret, 1U, (off_t)(secret - profile)) == 1 &&
                fsync(fd) == 0 && close(fd) == 0,
            "committing client mismatch must persist");
    ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
    require(run_rotate(&fixture, "00000000\n", NULL, NULL) != 0,
            "mismatched COMMITTING pair must fail closed");
    require(transaction_journal_exists(&fixture) &&
                rate_state_exists(&fixture, old_record.key_id),
            "mismatched COMMITTING recovery must preserve journal and old state");
    (void)memset(profile, 0, sizeof(profile));
    (void)memset(response, 0, sizeof(response));
    ocra_secret_record_clear(&old_record);
    fixture_destroy(&fixture);
}

static void test_revoke_cannot_be_undone_by_pending_rotation_recovery(void)
{
    struct enroll_fixture fixture;
    static const char invalid_response[] = "00000000\n";

    fixture_create(&fixture);
    require(run_add(&fixture) == 0,
            "credential for revoke resurrection regression must add");
    ocra_enroll_set_fault_for_tests(
        OCRA_ENROLL_FAULT_INTERRUPT_AFTER_CLIENT, 1U);
    require(run_rotate(&fixture, invalid_response, NULL, NULL) != 0,
            "rotation must leave a recoverable PREPARED transaction");
    require(run_server_only_command(&fixture, "revoke", TEST_SERVICE, NULL,
                                    NULL) == 0,
            "revoke must resolve the pending transaction and complete");
    require(!server_record_exists(&fixture, TEST_SERVICE),
            "completed revoke must remove the server credential");
    require(run_rotate(&fixture, invalid_response, NULL, NULL) != 0,
            "rotation after revoke must fail without a server credential");
    require(!server_record_exists(&fixture, TEST_SERVICE),
            "pending recovery must never resurrect a completed revoke");
    fixture_destroy(&fixture);
}

static void test_admin_lock_symlink_is_denied_without_touching_referent(void)
{
    static const char sentinel_body[] = "admin-lock-sentinel\n";
    struct enroll_fixture fixture;
    char lock_path[256];
    char sentinel_path[256];
    char buffer[sizeof(sentinel_body)];
    int sentinel_fd;

    fixture_create(&fixture);
    require(snprintf(lock_path, sizeof(lock_path), "%s/admin.lock",
                     fixture.server_path) > 0 &&
                snprintf(sentinel_path, sizeof(sentinel_path), "%s/sentinel",
                         fixture.root_path) > 0,
            "admin lock regression paths must format");
    sentinel_fd = open(sentinel_path,
                       O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                       0600);
    require(sentinel_fd >= 0 &&
                write(sentinel_fd, sentinel_body,
                      sizeof(sentinel_body) - 1U) ==
                    (ssize_t)(sizeof(sentinel_body) - 1U) &&
                close(sentinel_fd) == 0,
            "admin lock sentinel must be created");
    require(symlink(sentinel_path, lock_path) == 0,
            "admin lock symlink must be created");
    require(run_add(&fixture) != 0,
            "unsafe admin lock must deny the mutating operation");
    sentinel_fd = open(sentinel_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    require(sentinel_fd >= 0, "admin lock sentinel must reopen");
    (void)memset(buffer, 0, sizeof(buffer));
    require(read(sentinel_fd, buffer, sizeof(buffer)) ==
                    (ssize_t)(sizeof(sentinel_body) - 1U) &&
                memcmp(buffer, sentinel_body,
                       sizeof(sentinel_body) - 1U) == 0 &&
                close(sentinel_fd) == 0,
            "unsafe admin lock referent must remain unchanged");
    fixture_destroy(&fixture);
}

static void test_revoke_resolves_interrupted_add_before_dispatch(void)
{
    struct enroll_fixture fixture;

    fixture_create(&fixture);
    ocra_enroll_set_fault_for_tests(
        OCRA_ENROLL_FAULT_INTERRUPT_AFTER_ADD_SERVER, 1U);
    require(run_add(&fixture) != 0,
            "add interruption must leave its server half pending");
    require(transaction_journal_exists(&fixture) &&
                server_record_exists(&fixture, TEST_SERVICE),
            "interrupted add must expose journal and partial server target");
    ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
    require(run_server_only_command(&fixture, "revoke", TEST_SERVICE, NULL,
                                    NULL) != 0,
            "revoke must recover add before finding no committed credential");
    require(!transaction_journal_exists(&fixture) &&
                !server_record_exists(&fixture, TEST_SERVICE),
            "revoke dispatch must not treat an interrupted add as committed");
    fixture_destroy(&fixture);
}

static void test_revoke_recovery_respects_irreversible_committing_phase(void)
{
    struct enroll_fixture fixture;
    struct ocra_secret_record record;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];

    fixture_create(&fixture);
    require(run_add(&fixture) == 0,
            "credential for PREPARED revoke recovery must add");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &record) == 0,
            "PREPARED revoke record must load");
    ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_INTERRUPT_REVOKE, 1U);
    require(run_server_only_command(&fixture, "revoke", TEST_SERVICE, NULL,
                                    NULL) != 0,
            "revoke must interrupt after PREPARED");
    require(transaction_journal_exists(&fixture) &&
                server_record_exists(&fixture, TEST_SERVICE),
            "PREPARED revoke must retain recoverable credential and journal");
    ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
    require(run_server_only_command(&fixture, "inspect", TEST_SERVICE, NULL,
                                    NULL) == 0,
            "PREPARED recovery may cancel revoke and expose old credential");
    require(!transaction_journal_exists(&fixture) &&
                server_record_exists(&fixture, TEST_SERVICE),
            "PREPARED recovery must finish with old credential only");
    ocra_secret_record_clear(&record);
    fixture_destroy(&fixture);

    fixture_create(&fixture);
    require(run_add(&fixture) == 0,
            "credential for COMMITTING revoke recovery must add");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &record) == 0 &&
                ocra_rate_limit_reserve_at(fixture.rate_fd, TEST_UID_TEXT,
                                           TEST_SERVICE, record.key_id,
                                           challenge) == 0,
            "COMMITTING revoke record and rate state must exist");
    ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_INTERRUPT_REVOKE, 2U);
    require(run_server_only_command(&fixture, "revoke", TEST_SERVICE, NULL,
                                    NULL) != 0,
            "revoke must interrupt after COMMITTING");
    require(transaction_journal_exists(&fixture),
            "COMMITTING revoke must leave durable roll-forward intent");
    ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
    require(run_server_only_command(&fixture, "inspect", TEST_SERVICE, NULL,
                                    NULL) != 0,
            "inspection after COMMITTING must recover revoke then find absent");
    require(!transaction_journal_exists(&fixture) &&
                !server_record_exists(&fixture, TEST_SERVICE) &&
                !rate_state_exists(&fixture, record.key_id),
            "COMMITTING recovery must only converge to fully revoked");
    ocra_secret_record_clear(&record);
    fixture_destroy(&fixture);

    for (unsigned int occurrence = 3U; occurrence <= 4U; ++occurrence) {
        fixture_create(&fixture);
        require(run_add(&fixture) == 0 &&
                    ocra_secret_store_load_at(fixture.server_fd,
                                              TEST_UID_TEXT, TEST_SERVICE,
                                              &record) == 0 &&
                    ocra_rate_limit_reserve_at(
                        fixture.rate_fd, TEST_UID_TEXT, TEST_SERVICE,
                        record.key_id, challenge) == 0,
                "late COMMITTING revoke fixture must be complete");
        ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_INTERRUPT_REVOKE,
                                        occurrence);
        require(run_server_only_command(&fixture, "revoke", TEST_SERVICE,
                                        NULL, NULL) != 0 &&
                    transaction_journal_has_phase(&fixture, "committing"),
                "late revoke interruption must retain COMMITTING intent");
        ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
        require(run_server_only_command(&fixture, "inspect", TEST_SERVICE,
                                        NULL, NULL) != 0 &&
                    !transaction_journal_exists(&fixture) &&
                    !server_record_exists(&fixture, TEST_SERVICE) &&
                    !rate_state_exists(&fixture, record.key_id),
                "late COMMITTING recovery must converge idempotently");
        ocra_secret_record_clear(&record);
        fixture_destroy(&fixture);
    }
}

static void test_rotate_prepares_every_durable_participant_before_journal(void)
{
    static const struct {
        unsigned int occurrence;
        size_t server_entries;
        size_t transaction_entries;
        const char *phase;
    } checkpoints[] = {
        {1U, 1U, 0U, "preparing"},
        {2U, 2U, 0U, "preparing"},
        {3U, 2U, 1U, "preparing"},
        {4U, 3U, 1U, "preparing"},
        {5U, 3U, 2U, "preparing"},
        {6U, 3U, 2U, "prepared"},
    };
    size_t index;

    for (index = 0U; index < sizeof(checkpoints) / sizeof(checkpoints[0]);
         ++index) {
        struct enroll_fixture fixture;
        static const char invalid_response[] = "00000000\n";
        int server_scope_fd;
        int client_fd;
        int transaction_fd;
        struct stat transaction_status;

        fixture_create(&fixture);
        require(run_add(&fixture) == 0,
                "credential for preparation checkpoint must add");
        ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_INTERRUPT_PREPARE,
                                        checkpoints[index].occurrence);
        require(run_rotate(&fixture, invalid_response, NULL, NULL) != 0,
                "rotation must stop at requested preparation checkpoint");
        server_scope_fd = open_test_server_scope(&fixture);
        client_fd = open(fixture.client_path,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        require(client_fd >= 0,
                "preparation checkpoint client directory must open");
        transaction_fd = openat(client_fd,
                                ".ocra-admin-b0b1b2b3b4b5b6b7",
                                O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                    O_CLOEXEC);
        require(transaction_fd >= 0 &&
                    fstat(transaction_fd, &transaction_status) == 0 &&
                    (transaction_status.st_mode & 07777) == 0700,
                "preparation artifacts must use a private transaction directory");
        require(directory_entry_count(server_scope_fd) ==
                        checkpoints[index].server_entries &&
                    directory_entry_count(client_fd) == 2U &&
                    directory_entry_count(transaction_fd) ==
                        checkpoints[index].transaction_entries &&
                    transaction_journal_has_phase(&fixture,
                                                  checkpoints[index].phase),
                "PREPARED visibility must follow all durable participants");
        require(close(transaction_fd) == 0 && close(client_fd) == 0 &&
                    close(server_scope_fd) == 0,
                "preparation checkpoint directories must close");
        fixture_destroy(&fixture);
    }
}

static void test_rotation_recovery_survives_two_crashes_between_participants(void)
{
    struct enroll_fixture fixture;
    struct ocra_secret_record old_record;
    struct ocra_secret_record current;
    static const char invalid_response[] = "00000000\n";
    unsigned int crash;

    fixture_create(&fixture);
    require(run_add(&fixture) == 0 &&
                ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                          TEST_SERVICE, &old_record) == 0,
            "old pair for repeatable recovery must exist");
    ocra_enroll_set_fault_for_tests(
        OCRA_ENROLL_FAULT_INTERRUPT_AFTER_CLIENT, 1U);
    require(run_rotate(&fixture, invalid_response, NULL, NULL) != 0 &&
                transaction_journal_has_phase(&fixture, "prepared"),
            "rotation must leave PREPARED after client install");
    for (crash = 0U; crash < 2U; ++crash) {
        ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_INTERRUPT_RECOVERY,
                                        1U);
        require(run_server_only_command(&fixture, "inspect", TEST_SERVICE,
                                        NULL, NULL) != 0 &&
                    transaction_journal_exists(&fixture),
                "recovery crash must preserve journal for another attempt");
    }
    ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
    require(run_server_only_command(&fixture, "inspect", TEST_SERVICE, NULL,
                                    NULL) == 0,
            "third recovery attempt must finish before inspection");
    require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                      TEST_SERVICE, &current) == 0 &&
                records_match_for_test(&old_record, &current),
            "repeatable recovery must restore old server participant");
    load_client_record(&fixture, &current);
    require(records_match_for_test(&old_record, &current) &&
                !transaction_journal_exists(&fixture),
            "repeatable recovery must restore client and consume journal last");
    ocra_secret_record_clear(&current);
    ocra_secret_record_clear(&old_record);
    fixture_destroy(&fixture);
}

static void test_global_lock_serializes_inspect_and_aliased_profile_scope(void)
{
    struct enroll_fixture fixture;
    char alias_path[256];
    char challenge_line[96];
    static const char invalid_response[] = "00000000\n";
    int rotate_input[2];
    int rotate_output[2];
    int inspect_done[2];
    int alias_done[2];
    struct pollfd waiters[2];
    pid_t rotate_pid;
    pid_t inspect_pid;
    pid_t alias_pid;
    int status;

    fixture_create(&fixture);
    require(run_add(&fixture) == 0,
            "credential for global lock serialization must add");
    require(snprintf(alias_path, sizeof(alias_path), "%s//alice-sudo.conf",
                     fixture.client_path) > 0,
            "aliased client profile path must format");
    require(pipe(rotate_input) == 0 && pipe(rotate_output) == 0 &&
                pipe(inspect_done) == 0 && pipe(alias_done) == 0,
            "concurrency pipes must open");

    rotate_pid = fork();
    require(rotate_pid >= 0, "blocking rotation process must fork");
    if (rotate_pid == 0) {
        char *arguments[] = {"ocra-enroll", "rotate", "--user", TEST_USER,
                             "--service", TEST_SERVICE, "--client-profile",
                             fixture.profile_path};
        FILE *input;
        FILE *output;
        FILE *error;
        int result;

        (void)close(rotate_input[1]);
        (void)close(rotate_output[0]);
        (void)close(inspect_done[0]);
        (void)close(inspect_done[1]);
        (void)close(alias_done[0]);
        (void)close(alias_done[1]);
        input = fdopen(rotate_input[0], "r");
        output = fdopen(rotate_output[1], "w");
        error = tmpfile();
        if (input == NULL || output == NULL || error == NULL) {
            test_child_exit(2);
        }
        result = ocra_enroll_run_at_for_tests(
            8, arguments, input, output, error, fixture.server_fd,
            fixture.rate_fd);
        (void)fclose(input);
        (void)fclose(output);
        (void)fclose(error);
        test_child_exit(result != 0 ? 0 : 3);
    }
    require(close(rotate_input[0]) == 0 && close(rotate_output[1]) == 0,
            "parent must retain only rotation pipe endpoints");
    require(read_pipe_line(rotate_output[0], challenge_line,
                           sizeof(challenge_line)) == 0 &&
                strstr(challenge_line, "Confirmation challenge:") != NULL,
            "rotation must hold the global lock while awaiting confirmation");

    inspect_pid = fork();
    require(inspect_pid >= 0, "concurrent inspection process must fork");
    if (inspect_pid == 0) {
        int result;

        (void)close(inspect_done[0]);
        (void)close(alias_done[0]);
        (void)close(alias_done[1]);
        (void)close(rotate_input[1]);
        (void)close(rotate_output[0]);
        result = run_server_only_command(&fixture, "inspect", TEST_SERVICE,
                                         NULL, NULL);
        if (write(inspect_done[1], result == 0 ? "S" : "F", 1U) != 1) {
            test_child_exit(6);
        }
        (void)close(inspect_done[1]);
        test_child_exit(result == 0 ? 0 : 4);
    }
    require(close(inspect_done[1]) == 0,
            "parent inspection completion writer must close");

    alias_pid = fork();
    require(alias_pid >= 0, "aliased scope process must fork");
    if (alias_pid == 0) {
        int result;

        (void)close(alias_done[0]);
        (void)close(inspect_done[0]);
        (void)close(rotate_input[1]);
        (void)close(rotate_output[0]);
        result = run_add_scope(&fixture, "login", alias_path);
        if (write(alias_done[1], result != 0 ? "S" : "F", 1U) != 1) {
            test_child_exit(7);
        }
        (void)close(alias_done[1]);
        test_child_exit(result != 0 ? 0 : 5);
    }
    require(close(alias_done[1]) == 0,
            "parent alias completion writer must close");
    waiters[0].fd = inspect_done[0];
    waiters[0].events = POLLIN | POLLHUP;
    waiters[0].revents = 0;
    waiters[1].fd = alias_done[0];
    waiters[1].events = POLLIN | POLLHUP;
    waiters[1].revents = 0;
    require(poll(waiters, 2U, 150) == 0,
            "inspect and aliased scope must wait behind one global lock");
    require(write(rotate_input[1], invalid_response,
                  sizeof(invalid_response) - 1U) ==
                    (ssize_t)(sizeof(invalid_response) - 1U) &&
                close(rotate_input[1]) == 0,
            "parent must release the blocking confirmation read");
    require(waitpid(rotate_pid, &status, 0) == rotate_pid &&
                WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "blocking rotation must fail confirmation and release lock");
    require(waitpid(inspect_pid, &status, 0) == inspect_pid &&
                WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "queued inspection must complete after lock release");
    require(waitpid(alias_pid, &status, 0) == alias_pid &&
                WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "aliased-profile add must fail safely after serialization");
    require(close(rotate_output[0]) == 0 && close(inspect_done[0]) == 0 &&
                close(alias_done[0]) == 0,
            "concurrency parent pipe endpoints must close");
    require(server_record_exists(&fixture, TEST_SERVICE) &&
                !server_record_exists(&fixture, "login") &&
                !transaction_journal_exists(&fixture),
            "serialized operations must preserve one consistent scope/profile");
    fixture_destroy(&fixture);
}

static void test_recovery_rejects_replaced_original_client_directory(void)
{
    struct enroll_fixture fixture;
    char displaced_path[256];
    char alias_path[256];
    static const char invalid_response[] = "00000000\n";

    fixture_create(&fixture);
    require(run_add(&fixture) == 0,
            "credential for client identity recovery must add");
    ocra_enroll_set_fault_for_tests(
        OCRA_ENROLL_FAULT_INTERRUPT_AFTER_CLIENT, 1U);
    require(run_rotate(&fixture, invalid_response, NULL, NULL) != 0 &&
                transaction_journal_has_phase(&fixture, "prepared"),
            "client identity setup must leave PREPARED recovery");
    require(snprintf(displaced_path, sizeof(displaced_path), "%s.displaced",
                     fixture.client_path) > 0 &&
                snprintf(alias_path, sizeof(alias_path), "%s//alice-sudo.conf",
                         fixture.client_path) > 0,
            "client identity replacement paths must format");
    require(rename(fixture.client_path, displaced_path) == 0,
            "original client directory must move without changing its inode");
    make_directory(fixture.client_path);
    move_directory_files(displaced_path, fixture.client_path);
    ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
    require(run_add_scope(&fixture, "login", alias_path) != 0,
            "alias retry must not redirect recovery to a replacement inode");
    require(transaction_journal_has_phase(&fixture, "prepared") &&
                server_record_exists(&fixture, TEST_SERVICE) &&
                !server_record_exists(&fixture, "login"),
            "identity mismatch must fail closed with journal and scope intact");
    fixture_destroy(&fixture);
}

static void test_preparing_cleanup_is_repeatable_and_never_changes_targets(void)
{
    struct enroll_fixture fixture;
    struct ocra_secret_record old_record;
    struct ocra_secret_record current;
    static const char invalid_response[] = "00000000\n";
    unsigned int crash;

    fixture_create(&fixture);
    require(run_add(&fixture) == 0 &&
                ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                          TEST_SERVICE, &old_record) == 0,
            "old pair for PREPARING cleanup must exist");
    ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_INTERRUPT_PREPARE, 5U);
    require(run_rotate(&fixture, invalid_response, NULL, NULL) != 0 &&
                transaction_journal_has_phase(&fixture, "preparing"),
            "rotation must stop with all PREPARING artifacts durable");
    for (crash = 0U; crash < 4U; ++crash) {
        ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_INTERRUPT_RECOVERY,
                                        1U);
        require(run_server_only_command(&fixture, "inspect", TEST_SERVICE,
                                        NULL, NULL) != 0 &&
                    transaction_journal_has_phase(&fixture, "cleanup"),
                "each PREPARING cleanup crash must leave retryable intent");
        require(ocra_secret_store_load_at(fixture.server_fd, TEST_UID_TEXT,
                                          TEST_SERVICE, &current) == 0 &&
                    records_match_for_test(&old_record, &current),
                "PREPARING cleanup must never modify the server target");
        load_client_record(&fixture, &current);
        require(records_match_for_test(&old_record, &current),
                "PREPARING cleanup must never modify the client target");
    }
    ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
    require(run_server_only_command(&fixture, "inspect", TEST_SERVICE, NULL,
                                    NULL) == 0 &&
                !transaction_journal_exists(&fixture),
            "final PREPARING recovery must remove journal last");
    ocra_secret_record_clear(&current);
    ocra_secret_record_clear(&old_record);
    fixture_destroy(&fixture);
}

static void test_rotate_fault_matrix_converges_without_mixed_pair(void)
{
    static const enum ocra_enroll_fault_operation matrices[] = {
        OCRA_ENROLL_FAULT_WRITE_PARTIAL,
        OCRA_ENROLL_FAULT_FSYNC_FILE,
        OCRA_ENROLL_FAULT_RENAME,
        OCRA_ENROLL_FAULT_FSYNC_DIRECTORY,
    };
    size_t matrix;

    for (matrix = 0U; matrix < sizeof(matrices) / sizeof(matrices[0]);
         ++matrix) {
        struct enroll_fixture calibration;
        char calibration_response[10U];
        unsigned int last_occurrence;
        unsigned int occurrence;

        fixture_create(&calibration);
        require(run_add(&calibration) == 0,
                "rotation matrix calibration credential must add");
        compute_second_credential_response(calibration_response);
        ocra_enroll_set_fault_for_tests(matrices[matrix], UINT_MAX);
        require(run_rotate(&calibration, calibration_response, NULL, NULL) ==
                    0,
                "rotation matrix calibration must complete without injection");
        last_occurrence = ocra_enroll_get_fault_seen_for_tests();
        require(last_occurrence > 0U,
                "rotation matrix must observe at least one boundary");
        fixture_destroy(&calibration);

        for (occurrence = 1U; occurrence <= last_occurrence; ++occurrence) {
            struct enroll_fixture fixture;
            struct ocra_secret_record old_record;
            struct ocra_secret_record server_record;
            struct ocra_secret_record client_record;
            char response[10U];
            char rate_challenge[OCRA_CHALLENGE_DIGITS + 1U];
            int kept_old;

            fixture_create(&fixture);
            require(run_add(&fixture) == 0 &&
                        ocra_secret_store_load_at(
                            fixture.server_fd, TEST_UID_TEXT, TEST_SERVICE,
                            &old_record) == 0 &&
                        ocra_rate_limit_reserve_at(
                            fixture.rate_fd, TEST_UID_TEXT, TEST_SERVICE,
                            old_record.key_id, rate_challenge) == 0,
                    "rotation fault matrix fixture must be complete");
            compute_second_credential_response(response);
            ocra_enroll_set_fault_for_tests(matrices[matrix], occurrence);
            require(run_rotate(&fixture, response, NULL, NULL) != 0,
                    "injected rotation persistence boundary must fail");
            ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
            require(run_server_only_command(&fixture, "inspect", TEST_SERVICE,
                                            NULL, NULL) == 0,
                    "next invocation must complete pending recovery first");
            require(ocra_secret_store_load_at(
                        fixture.server_fd, TEST_UID_TEXT, TEST_SERVICE,
                        &server_record) == 0,
                    "fault matrix server target must remain readable");
            load_client_record(&fixture, &client_record);
            require(records_match_for_test(&server_record, &client_record) &&
                        !transaction_journal_exists(&fixture),
                    "fault recovery must converge to one matching pair");
            kept_old = records_match_for_test(&old_record, &server_record);
            require(rate_state_exists(&fixture, old_record.key_id) == kept_old,
                    "old rate state must follow rollback or committed retire");
            (void)memset(response, 0, sizeof(response));
            ocra_secret_record_clear(&client_record);
            ocra_secret_record_clear(&server_record);
            ocra_secret_record_clear(&old_record);
            fixture_destroy(&fixture);
        }
    }
}

static void test_add_fault_matrix_recalibrates_and_converges(void)
{
    static const enum ocra_enroll_fault_operation matrices[] = {
        OCRA_ENROLL_FAULT_WRITE_PARTIAL,
        OCRA_ENROLL_FAULT_FSYNC_FILE,
        OCRA_ENROLL_FAULT_RENAME,
        OCRA_ENROLL_FAULT_FSYNC_DIRECTORY,
    };
    size_t matrix;

    for (matrix = 0U; matrix < sizeof(matrices) / sizeof(matrices[0]);
         ++matrix) {
        struct enroll_fixture calibration;
        unsigned int last_occurrence;
        unsigned int occurrence;

        fixture_create(&calibration);
        ocra_enroll_set_fault_for_tests(matrices[matrix], UINT_MAX);
        require(run_add(&calibration) == 0,
                "add matrix calibration must complete without injection");
        last_occurrence = ocra_enroll_get_fault_seen_for_tests();
        require(last_occurrence > 0U,
                "add matrix must observe at least one boundary");
        fixture_destroy(&calibration);

        for (occurrence = 1U; occurrence <= last_occurrence; ++occurrence) {
            struct enroll_fixture fixture;
            struct ocra_secret_record server_record;
            struct ocra_secret_record client_record;
            struct stat status;
            int inspect_result;

            fixture_create(&fixture);
            ocra_enroll_set_fault_for_tests(matrices[matrix], occurrence);
            require(run_add(&fixture) != 0,
                    "injected add persistence boundary must fail");
            ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
            inspect_result = run_server_only_command(
                &fixture, "inspect", TEST_SERVICE, NULL, NULL);
            if (server_record_exists(&fixture, TEST_SERVICE)) {
                require(inspect_result == 0 &&
                            ocra_secret_store_load_at(
                                fixture.server_fd, TEST_UID_TEXT,
                                TEST_SERVICE, &server_record) == 0,
                        "committed add fault must retain readable server state");
                load_client_record(&fixture, &client_record);
                require(records_match_for_test(&server_record,
                                               &client_record),
                        "committed add fault must converge to a matching pair");
                ocra_secret_record_clear(&client_record);
                ocra_secret_record_clear(&server_record);
            } else {
                require(inspect_result != 0 &&
                            fstatat(AT_FDCWD, fixture.profile_path, &status,
                                    AT_SYMLINK_NOFOLLOW) != 0 &&
                            errno == ENOENT && run_add(&fixture) == 0,
                        "rolled-back add fault must permit a clean retry");
            }
            require(!transaction_journal_exists(&fixture),
                    "add fault convergence must consume recovery intent");
            fixture_destroy(&fixture);
        }
    }
}

static void test_revoke_fault_matrix_recalibrates_and_converges(void)
{
    static const enum ocra_enroll_fault_operation matrices[] = {
        OCRA_ENROLL_FAULT_WRITE_PARTIAL,
        OCRA_ENROLL_FAULT_FSYNC_FILE,
        OCRA_ENROLL_FAULT_RENAME,
        OCRA_ENROLL_FAULT_FSYNC_DIRECTORY,
    };
    size_t matrix;

    for (matrix = 0U; matrix < sizeof(matrices) / sizeof(matrices[0]);
         ++matrix) {
        struct enroll_fixture calibration;
        unsigned int last_occurrence;
        unsigned int occurrence;

        fixture_create(&calibration);
        require(run_add(&calibration) == 0,
                "revoke matrix calibration credential must add");
        ocra_enroll_set_fault_for_tests(matrices[matrix], UINT_MAX);
        require(run_server_only_command(&calibration, "revoke", TEST_SERVICE,
                                        NULL, NULL) == 0,
                "revoke matrix calibration must complete without injection");
        last_occurrence = ocra_enroll_get_fault_seen_for_tests();
        require(last_occurrence > 0U,
                "revoke matrix must observe at least one boundary");
        fixture_destroy(&calibration);

        for (occurrence = 1U; occurrence <= last_occurrence; ++occurrence) {
            struct enroll_fixture fixture;
            struct ocra_secret_record old_record;
            struct ocra_secret_record current;
            char challenge[OCRA_CHALLENGE_DIGITS + 1U];
            int inspect_result;

            fixture_create(&fixture);
            require(run_add(&fixture) == 0 &&
                        ocra_secret_store_load_at(
                            fixture.server_fd, TEST_UID_TEXT, TEST_SERVICE,
                            &old_record) == 0 &&
                        ocra_rate_limit_reserve_at(
                            fixture.rate_fd, TEST_UID_TEXT, TEST_SERVICE,
                            old_record.key_id, challenge) == 0,
                    "revoke matrix fixture must include credential and rate state");
            ocra_enroll_set_fault_for_tests(matrices[matrix], occurrence);
            require(run_server_only_command(&fixture, "revoke", TEST_SERVICE,
                                            NULL, NULL) != 0,
                    "injected revoke persistence boundary must fail");
            ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
            inspect_result = run_server_only_command(
                &fixture, "inspect", TEST_SERVICE, NULL, NULL);
            if (server_record_exists(&fixture, TEST_SERVICE)) {
                require(inspect_result == 0 &&
                            ocra_secret_store_load_at(
                                fixture.server_fd, TEST_UID_TEXT,
                                TEST_SERVICE, &current) == 0 &&
                            records_match_for_test(&old_record, &current) &&
                            rate_state_exists(&fixture, old_record.key_id),
                        "rolled-back revoke must preserve credential and rate state");
                ocra_secret_record_clear(&current);
            } else {
                require(inspect_result != 0 &&
                            !rate_state_exists(&fixture, old_record.key_id),
                        "committing revoke must retire credential and rate state");
            }
            require(!transaction_journal_exists(&fixture),
                    "revoke fault convergence must consume recovery intent");
            ocra_secret_record_clear(&old_record);
            fixture_destroy(&fixture);
        }
    }
}

static void test_recovery_fault_matrix_recalibrates_and_converges(void)
{
    static const enum ocra_enroll_fault_operation matrices[] = {
        OCRA_ENROLL_FAULT_WRITE_PARTIAL,
        OCRA_ENROLL_FAULT_FSYNC_FILE,
        OCRA_ENROLL_FAULT_RENAME,
        OCRA_ENROLL_FAULT_FSYNC_DIRECTORY,
    };
    size_t matrix;

    for (matrix = 0U; matrix < sizeof(matrices) / sizeof(matrices[0]);
         ++matrix) {
        struct enroll_fixture calibration;
        static const char invalid_response[] = "00000000\n";
        unsigned int last_occurrence;
        unsigned int occurrence;

        fixture_create(&calibration);
        require(run_add(&calibration) == 0,
                "recovery matrix calibration credential must add");
        ocra_enroll_set_fault_for_tests(
            OCRA_ENROLL_FAULT_INTERRUPT_AFTER_CLIENT, 1U);
        require(run_rotate(&calibration, invalid_response, NULL, NULL) != 0 &&
                    transaction_journal_has_phase(&calibration, "prepared"),
                "recovery matrix calibration must leave PREPARED intent");
        ocra_enroll_set_fault_for_tests(matrices[matrix], UINT_MAX);
        require(run_server_only_command(&calibration, "inspect", TEST_SERVICE,
                                        NULL, NULL) == 0,
                "recovery matrix calibration must converge without injection");
        last_occurrence = ocra_enroll_get_fault_seen_for_tests();
        require(last_occurrence > 0U,
                "recovery matrix must observe at least one boundary");
        fixture_destroy(&calibration);

        for (occurrence = 1U; occurrence <= last_occurrence; ++occurrence) {
            struct enroll_fixture fixture;
            struct ocra_secret_record old_record;
            struct ocra_secret_record server_record;
            struct ocra_secret_record client_record;

            fixture_create(&fixture);
            require(run_add(&fixture) == 0 &&
                        ocra_secret_store_load_at(
                            fixture.server_fd, TEST_UID_TEXT, TEST_SERVICE,
                            &old_record) == 0,
                    "recovery matrix fixture must start with old state");
            ocra_enroll_set_fault_for_tests(
                OCRA_ENROLL_FAULT_INTERRUPT_AFTER_CLIENT, 1U);
            require(run_rotate(&fixture, invalid_response, NULL, NULL) != 0 &&
                        transaction_journal_has_phase(&fixture, "prepared"),
                    "recovery matrix fixture must leave PREPARED intent");
            ocra_enroll_set_fault_for_tests(matrices[matrix], occurrence);
            require(run_server_only_command(&fixture, "inspect", TEST_SERVICE,
                                            NULL, NULL) != 0,
                    "injected recovery persistence boundary must fail");
            ocra_enroll_set_fault_for_tests(OCRA_ENROLL_FAULT_NONE, 0U);
            require(run_server_only_command(&fixture, "inspect", TEST_SERVICE,
                                            NULL, NULL) == 0 &&
                        ocra_secret_store_load_at(
                            fixture.server_fd, TEST_UID_TEXT, TEST_SERVICE,
                            &server_record) == 0,
                    "second recovery invocation must converge");
            load_client_record(&fixture, &client_record);
            require(records_match_for_test(&old_record, &server_record) &&
                        records_match_for_test(&old_record, &client_record) &&
                        !transaction_journal_exists(&fixture),
                    "recovery fault matrix must converge to the old pair");
            ocra_secret_record_clear(&client_record);
            ocra_secret_record_clear(&server_record);
            ocra_secret_record_clear(&old_record);
            fixture_destroy(&fixture);
        }
    }
}

int main(void)
{
    test_stream_capture_preserves_embedded_nul_length();
    test_admin_lock_cleanup_attempts_every_step_after_failures();
    test_add_recovers_crashes_inside_each_staged_write();
    test_add_preserves_precreated_client_transaction_name();
    test_add_preserves_precreated_transaction_symlink_and_hardlink();
    test_owner_mismatch_rejects_user_owned_transaction_directory();
    test_rotation_recovers_partial_restore_stages();
    test_revoke_recovers_partial_backup_stage();
    test_add_creates_compatible_server_and_client_records();
    test_cli_rejects_secret_options_relative_paths_and_random_failure();
    test_add_rejects_unknown_user_invalid_service_and_non_root();
    test_add_rejects_collision_without_changing_existing_pair();
    test_add_rejects_symlink_target_without_touching_referent();
    test_add_rolls_back_each_persistence_boundary();
    test_rotate_confirms_externally_then_retires_old_credential();
    test_failed_rotation_confirmation_restores_old_pair();
    test_inspect_exposes_only_non_sensitive_metadata();
    test_revoke_removes_only_requested_scope_and_old_rate_state();
    test_rate_cleanup_failure_rolls_forward_committing_operations();
    test_revoke_rejects_symlink_rate_state_without_touching_referent();
    test_next_rotation_recovers_interrupted_client_install();
    test_add_overwrite_requires_flag_and_external_confirmation();
    test_next_rotation_rolls_forward_committing_transaction();
    test_next_add_recovers_interrupted_server_install();
    test_committing_recovery_rejects_mismatched_new_pair();
    test_admin_lock_symlink_is_denied_without_touching_referent();
    test_revoke_resolves_interrupted_add_before_dispatch();
    test_revoke_recovery_respects_irreversible_committing_phase();
    test_rotate_prepares_every_durable_participant_before_journal();
    test_rotation_recovery_survives_two_crashes_between_participants();
    test_global_lock_serializes_inspect_and_aliased_profile_scope();
    test_recovery_rejects_replaced_original_client_directory();
    test_preparing_cleanup_is_repeatable_and_never_changes_targets();
    test_rotate_fault_matrix_converges_without_mixed_pair();
    test_add_fault_matrix_recalibrates_and_converges();
    test_revoke_fault_matrix_recalibrates_and_converges();
    test_recovery_fault_matrix_recalibrates_and_converges();
    test_revoke_cannot_be_undone_by_pending_rotation_recovery();
    return EXIT_SUCCESS;
}
