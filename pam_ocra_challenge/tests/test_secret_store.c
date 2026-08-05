#define _GNU_SOURCE

#include "../scope.h"
#include "../secret_store.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static const char valid_record_text[] =
    "version=1\n"
    "suite=OCRA-1:HOTP-SHA256-8:QN10\n"
    "key_id=0123456789abcdef\n"
    "secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    "enabled=yes\n";

struct store_fixture {
    char root_path[128];
    int root_fd;
    int users_fd;
    int uid_fd;
};

static dev_t wrong_owner_device;
static ino_t wrong_owner_inode;
static int alter_owner_gid;

struct mutation_context {
    int uid_fd;
    int replace_path;
};

static void require(int condition, const char *message)
{
    if (!condition) {
        (void)fprintf(stderr, "test failure: %s\n", message);
        exit(EXIT_FAILURE);
    }
}

static int memory_is_zero(const void *memory, size_t length)
{
    const unsigned char *bytes = memory;
    size_t index;

    for (index = 0U; index < length; ++index) {
        if (bytes[index] != 0U) {
            return 0;
        }
    }
    return 1;
}

static void require_parse_rejected(const unsigned char *data, size_t length,
                                   const char *message)
{
    struct ocra_secret_record record;

    memset(&record, 0xa5, sizeof(record));
    require(ocra_secret_store_parse_for_tests(data, length, &record) != 0,
            message);
    require(memory_is_zero(&record, sizeof(record)),
            "parser failure must clear the complete output record");
}

static void write_all(int fd, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    size_t offset = 0U;

    while (offset < length) {
        ssize_t count = write(fd, bytes + offset, length - offset);

        require(count > 0, "fixture write must succeed");
        offset += (size_t)count;
    }
}

static void fixture_create(struct store_fixture *fixture)
{
    char template[] = "/tmp/ocra-secret-store-XXXXXX";
    char *path = mkdtemp(template);

    require(path != NULL, "temporary store root must be created");
    require(strlen(path) < sizeof(fixture->root_path),
            "temporary path must fit fixture storage");
    (void)strcpy(fixture->root_path, path);
    require(chmod(path, 0700) == 0, "store root mode must be set");
    fixture->root_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(fixture->root_fd >= 0, "store root must open");
    require(mkdirat(fixture->root_fd, "users", 0700) == 0,
            "users directory must be created");
    fixture->users_fd = openat(fixture->root_fd, "users",
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(fixture->users_fd >= 0, "users directory must open");
    require(mkdirat(fixture->users_fd, "1000", 0700) == 0,
            "UID directory must be created");
    fixture->uid_fd = openat(fixture->users_fd, "1000",
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(fixture->uid_fd >= 0, "UID directory must open");
}

static void fixture_write_valid_file(struct store_fixture *fixture,
                                     const char *name)
{
    int fd = openat(fixture->uid_fd, name,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

    require(fd >= 0, "valid fixture file must be created");
    require(fchmod(fd, 0600) == 0, "fixture file mode must be exact");
    write_all(fd, valid_record_text, sizeof(valid_record_text) - 1U);
    require(close(fd) == 0, "fixture file must close");
}

static void fixture_write_bytes(struct store_fixture *fixture,
                                const unsigned char *data, size_t length)
{
    int fd = openat(fixture->uid_fd, "login.conf",
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

    require(fd >= 0, "fixture byte file must be created");
    require(fchmod(fd, 0600) == 0, "fixture byte file mode must be exact");
    write_all(fd, data, length);
    require(close(fd) == 0, "fixture byte file must close");
}

static void fixture_destroy(struct store_fixture *fixture)
{
    (void)unlinkat(fixture->uid_fd, "login.conf", 0);
    (void)unlinkat(fixture->uid_fd, "other.conf", 0);
    require(close(fixture->uid_fd) == 0, "UID descriptor must close");
    require(unlinkat(fixture->users_fd, "1000", AT_REMOVEDIR) == 0,
            "UID directory must be removed");
    require(close(fixture->users_fd) == 0, "users descriptor must close");
    require(unlinkat(fixture->root_fd, "users", AT_REMOVEDIR) == 0,
            "users directory must be removed");
    require(close(fixture->root_fd) == 0, "root descriptor must close");
    require(rmdir(fixture->root_path) == 0,
            "temporary store root must be removed");
}

static void require_store_rejected(struct store_fixture *fixture,
                                   const char *message)
{
    struct ocra_secret_record record;

    memset(&record, 0xa5, sizeof(record));
    require(ocra_secret_store_load_at(fixture->root_fd, "1000", "login",
                                      &record) != 0,
            message);
    require(memory_is_zero(&record, sizeof(record)),
            "store failure must clear the complete output record");
}

static int fstat_with_wrong_file_owner(int fd, struct stat *status)
{
    int result = fstat(fd, status);

    if (result == 0 && status->st_dev == wrong_owner_device &&
        status->st_ino == wrong_owner_inode) {
        if (alter_owner_gid != 0) {
            status->st_gid =
                status->st_gid == (gid_t)0 ? (gid_t)1 : (gid_t)0;
        } else {
            status->st_uid =
                status->st_uid == (uid_t)0 ? (uid_t)1 : (uid_t)0;
        }
    }
    return result;
}

static void require_wrong_ownership_rejected(struct store_fixture *fixture,
                                             int target_fd, int wrong_gid,
                                             const char *message)
{
    struct stat status;

    require(fstat(target_fd, &status) == 0,
            "ownership target metadata must load");
    wrong_owner_device = status.st_dev;
    wrong_owner_inode = status.st_ino;
    alter_owner_gid = wrong_gid;
    ocra_secret_store_set_stat_provider_for_tests(fstat_with_wrong_file_owner);
    require_store_rejected(fixture, message);
    ocra_secret_store_reset_stat_provider_for_tests();
}

static void mutate_secret_after_open(int file_fd, void *opaque)
{
    static const char changed_record[] =
        "version=1\n"
        "suite=OCRA-1:HOTP-SHA256-8:QN10\n"
        "key_id=fedcba9876543210\n"
        "secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "enabled=yes\n";
    struct mutation_context *context = opaque;
    const struct timespec changed_times[2] = {
        {(time_t)1234567890, 0L}, {(time_t)1234567890, 0L}};
    int fd;

    (void)file_fd;
    if (context->replace_path != 0) {
        require(renameat(context->uid_fd, "login.conf", context->uid_fd,
                         "other.conf") == 0,
                "opened secret must move during replacement race");
        fd = openat(context->uid_fd, "login.conf",
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        require(fd >= 0, "replacement secret must be created");
        write_all(fd, changed_record, sizeof(changed_record) - 1U);
    } else {
        fd = openat(context->uid_fd, "login.conf",
                    O_WRONLY | O_TRUNC | O_CLOEXEC);
        require(fd >= 0, "opened secret must reopen for mutation race");
        write_all(fd, changed_record, sizeof(changed_record) - 1U);
    }
    require(fsync(fd) == 0, "racing fixture mutation must reach inode");
    require(futimens(fd, changed_times) == 0,
            "racing fixture must force a distinct timestamp");
    require(close(fd) == 0, "racing fixture descriptor must close");
}

static void test_scope_accepts_only_canonical_uid_and_safe_service(void)
{
    uid_t uid = (uid_t)123U;
    char long_service[OCRA_SERVICE_MAX_LENGTH + 2U];

    require(ocra_scope_parse_uid("0", &uid) == 0 && uid == (uid_t)0,
            "UID zero must be canonical and valid");
    require(ocra_scope_parse_uid("4294967295", &uid) == 0 &&
                (uintmax_t)uid == UINT32_MAX,
            "maximum 32-bit UID must be valid");
    require(ocra_scope_parse_uid("", &uid) != 0,
            "empty UID must be rejected");
    require(ocra_scope_parse_uid("00", &uid) != 0,
            "UID with a leading zero must be rejected");
    require(ocra_scope_parse_uid("+1", &uid) != 0,
            "signed UID must be rejected");
    require(ocra_scope_parse_uid("4294967296", &uid) != 0,
            "UID beyond 32 bits must be rejected");
    require(ocra_scope_parse_uid("1x", &uid) != 0,
            "UID with non-digits must be rejected");
    require(ocra_scope_parse_uid("1", NULL) != 0,
            "UID parser needs an output location");

    require(ocra_scope_validate_service("login") == 0,
            "alphanumeric service must be valid");
    require(ocra_scope_validate_service("sshd-key_2") == 0,
            "dash and underscore must be valid service characters");
    require(ocra_scope_validate_service("") != 0,
            "empty service must be rejected");
    require(ocra_scope_validate_service("../login") != 0,
            "service traversal must be rejected");
    require(ocra_scope_validate_service("a.b") != 0,
            "dot must be rejected");
    require(ocra_scope_validate_service("a/b") != 0,
            "slash must be rejected");
    require(ocra_scope_validate_service("a b") != 0,
            "space must be rejected");
    require(ocra_scope_validate_service(NULL) != 0,
            "NULL service must be rejected");

    memset(long_service, 'a', sizeof(long_service));
    long_service[sizeof(long_service) - 1U] = '\0';
    require(ocra_scope_validate_service(long_service) != 0,
            "overlong service must be rejected");
}

static void test_parser_decodes_complete_valid_record(void)
{
    static const unsigned char input[] =
        "version=1\n"
        "suite=OCRA-1:HOTP-SHA256-8:QN10\n"
        "key_id=0123456789abcdef\n"
        "secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "enabled=yes\n";
    struct ocra_secret_record record;
    size_t index;

    memset(&record, 0xa5, sizeof(record));
    require(ocra_secret_store_parse_for_tests(input, sizeof(input) - 1U,
                                              &record) == 0,
            "complete valid record must parse");
    require(strcmp(record.key_id, "0123456789abcdef") == 0,
            "valid key identifier must be returned");
    for (index = 0U; index < sizeof(record.secret); ++index) {
        require(record.secret[index] == 0U,
                "all-A Base32 secret must decode to zero bytes");
    }
    ocra_secret_record_clear(&record);
}

static void test_parser_rejects_malformed_structure_and_clears_output(void)
{
    static const unsigned char crlf[] =
        "version=1\r\n"
        "suite=OCRA-1:HOTP-SHA256-8:QN10\r\n"
        "key_id=0123456789abcdef\r\n"
        "secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n"
        "enabled=yes\r\n";
    static const unsigned char duplicate[] =
        "version=1\nversion=1\n"
        "suite=OCRA-1:HOTP-SHA256-8:QN10\n"
        "key_id=0123456789abcdef\n"
        "secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "enabled=yes\n";
    static const unsigned char unknown[] =
        "version=1\n"
        "suite=OCRA-1:HOTP-SHA256-8:QN10\n"
        "key_id=0123456789abcdef\n"
        "secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "enabled=yes\nextra=no\n";
    static const unsigned char missing[] =
        "version=1\n"
        "suite=OCRA-1:HOTP-SHA256-8:QN10\n"
        "key_id=0123456789abcdef\n"
        "secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
    static const unsigned char reordered[] =
        "suite=OCRA-1:HOTP-SHA256-8:QN10\n"
        "version=1\n"
        "key_id=0123456789abcdef\n"
        "secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "enabled=yes\n";
    static const unsigned char no_final_lf[] =
        "version=1\n"
        "suite=OCRA-1:HOTP-SHA256-8:QN10\n"
        "key_id=0123456789abcdef\n"
        "secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "enabled=yes";
    unsigned char nul_input[] =
        "version=1\n"
        "suite=OCRA-1:HOTP-SHA256-8:QN10\n"
        "key_id=0123456789abcdef\n"
        "secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "enabled=yes\n";
    unsigned char oversized[OCRA_SECRET_FILE_MAX + 1U];
    unsigned char long_line[OCRA_SECRET_LINE_MAX + 2U];

    require_parse_rejected(NULL, 1U, "NULL input must be rejected");
    require_parse_rejected((const unsigned char *)"", 0U,
                           "empty input must be rejected");
    require_parse_rejected(crlf, sizeof(crlf) - 1U,
                           "CRLF is forbidden by the LF-only policy");
    require_parse_rejected(duplicate, sizeof(duplicate) - 1U,
                           "duplicate fields must be rejected");
    require_parse_rejected(unknown, sizeof(unknown) - 1U,
                           "unknown fields must be rejected");
    require_parse_rejected(missing, sizeof(missing) - 1U,
                           "missing fields must be rejected");
    require_parse_rejected(reordered, sizeof(reordered) - 1U,
                           "fields outside the exact layout must be rejected");
    require_parse_rejected(no_final_lf, sizeof(no_final_lf) - 1U,
                           "record without final LF must be rejected");

    nul_input[10] = '\0';
    require_parse_rejected(nul_input, sizeof(nul_input) - 1U,
                           "embedded NUL must be rejected");

    memset(oversized, 'x', sizeof(oversized));
    require_parse_rejected(oversized, sizeof(oversized),
                           "oversized file must be rejected");

    memset(long_line, 'x', sizeof(long_line));
    long_line[sizeof(long_line) - 1U] = '\n';
    require_parse_rejected(long_line, sizeof(long_line),
                           "overlong line must be rejected");
}

static void test_parser_decodes_nonzero_canonical_base32(void)
{
    static const unsigned char input[] =
        "version=1\n"
        "suite=OCRA-1:HOTP-SHA256-8:QN10\n"
        "key_id=fedcba9876543210\n"
        "secret=AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ\n"
        "enabled=yes\n";
    struct ocra_secret_record record;
    size_t index;

    memset(&record, 0xa5, sizeof(record));
    require(ocra_secret_store_parse_for_tests(input, sizeof(input) - 1U,
                                              &record) == 0,
            "canonical nonzero Base32 record must parse");
    require(strcmp(record.key_id, "fedcba9876543210") == 0,
            "parser must return the configured key identifier");
    for (index = 0U; index < sizeof(record.secret); ++index) {
        require(record.secret[index] == (unsigned char)index,
                "Base32 must decode to the independently expected byte");
    }
    ocra_secret_record_clear(&record);
}

static void test_parser_rejects_invalid_field_values(void)
{
    static const char *const invalid[] = {
        "version=2\nsuite=OCRA-1:HOTP-SHA256-8:QN10\nkey_id=0123456789abcdef\nsecret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nenabled=yes\n",
        "version=1\nsuite=OCRA-1:HOTP-SHA1-8:QN10\nkey_id=0123456789abcdef\nsecret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nenabled=yes\n",
        "version=1\nsuite=OCRA-1:HOTP-SHA256-8:QN10\nkey_id=0123456789abcdef\nsecret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nenabled=no\n",
        "version=1\nsuite=OCRA-1:HOTP-SHA256-8:QN10\nkey_id=0123456789abcde\nsecret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nenabled=yes\n",
        "version=1\nsuite=OCRA-1:HOTP-SHA256-8:QN10\nkey_id=0123456789abcdef0\nsecret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nenabled=yes\n",
        "version=1\nsuite=OCRA-1:HOTP-SHA256-8:QN10\nkey_id=0123456789abcdeg\nsecret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nenabled=yes\n",
        "version=1\nsuite=OCRA-1:HOTP-SHA256-8:QN10\nkey_id=0123456789abcdef\nsecret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nenabled=yes\n",
        "version=1\nsuite=OCRA-1:HOTP-SHA256-8:QN10\nkey_id=0123456789abcdef\nsecret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nenabled=yes\n",
        "version=1\nsuite=OCRA-1:HOTP-SHA256-8:QN10\nkey_id=0123456789abcdef\nsecret=aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nenabled=yes\n",
        "version=1\nsuite=OCRA-1:HOTP-SHA256-8:QN10\nkey_id=0123456789abcdef\nsecret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nenabled=yes\n",
        "version=1\nsuite=OCRA-1:HOTP-SHA256-8:QN10\nkey_id=0123456789abcdef\nsecret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \nenabled=yes\n",
        "version=1\nsuite=OCRA-1:HOTP-SHA256-8:QN10\nkey_id=0123456789abcdef\nsecret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAR\nenabled=yes\n"};
    size_t index;

    for (index = 0U; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        require_parse_rejected((const unsigned char *)invalid[index],
                               strlen(invalid[index]),
                               "invalid field value must be rejected");
    }
}

static void test_store_loads_valid_file_and_fails_closed_when_absent(void)
{
    struct store_fixture fixture;
    struct ocra_secret_record record;

    fixture_create(&fixture);
    fixture_write_valid_file(&fixture, "login.conf");

    memset(&record, 0xa5, sizeof(record));
    require(ocra_secret_store_load_at(fixture.root_fd, "1000", "login",
                                      &record) == 0,
            "valid protected secret file must load");
    require(strcmp(record.key_id, "0123456789abcdef") == 0,
            "loaded record must expose its key identifier");
    require(memory_is_zero(record.secret, sizeof(record.secret)),
            "loaded all-A secret must decode to zero bytes");

    require(unlinkat(fixture.uid_fd, "login.conf", 0) == 0,
            "valid fixture file must be removable");
    memset(&record, 0xa5, sizeof(record));
    require(ocra_secret_store_load_at(fixture.root_fd, "1000", "login",
                                      &record) != 0,
            "missing secret file must fail closed");
    require(memory_is_zero(&record, sizeof(record)),
            "missing file failure must clear output");

    require(close(fixture.uid_fd) == 0, "UID descriptor must close");
    require(unlinkat(fixture.users_fd, "1000", AT_REMOVEDIR) == 0,
            "UID directory must be removable");
    fixture.uid_fd = openat(fixture.users_fd, ".",
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(fixture.uid_fd >= 0, "cleanup descriptor must open");
    memset(&record, 0xa5, sizeof(record));
    require(ocra_secret_store_load_at(fixture.root_fd, "1000", "login",
                                      &record) != 0,
            "missing UID directory must fail closed");
    require(memory_is_zero(&record, sizeof(record)),
            "missing directory failure must clear output");
    require(close(fixture.uid_fd) == 0, "cleanup descriptor must close");
    fixture.uid_fd = -1;
    require(close(fixture.users_fd) == 0, "users descriptor must close");
    require(unlinkat(fixture.root_fd, "users", AT_REMOVEDIR) == 0,
            "users directory must be removed");
    require(close(fixture.root_fd) == 0, "root descriptor must close");
    require(rmdir(fixture.root_path) == 0,
            "temporary store root must be removed");
}

static void test_store_requires_exact_modes_and_expected_ownership(void)
{
    struct store_fixture fixture;
    int file_fd;

    fixture_create(&fixture);
    fixture_write_valid_file(&fixture, "login.conf");

    require_wrong_ownership_rejected(&fixture, fixture.root_fd, 0,
                                     "wrong store-root uid must be rejected");
    require_wrong_ownership_rejected(&fixture, fixture.root_fd, 1,
                                     "wrong store-root gid must be rejected");
    require_wrong_ownership_rejected(&fixture, fixture.users_fd, 0,
                                     "wrong users-directory uid must fail");
    require_wrong_ownership_rejected(&fixture, fixture.users_fd, 1,
                                     "wrong users-directory gid must fail");
    require_wrong_ownership_rejected(&fixture, fixture.uid_fd, 0,
                                     "wrong UID-directory uid must fail");
    require_wrong_ownership_rejected(&fixture, fixture.uid_fd, 1,
                                     "wrong UID-directory gid must fail");

    require(fchmod(fixture.root_fd, 0755) == 0, "root mode must change");
    require_store_rejected(&fixture, "store root mode 0755 must be rejected");
    require(fchmod(fixture.root_fd, 0700) == 0, "root mode must restore");

    require(fchmod(fixture.users_fd, 0755) == 0, "users mode must change");
    require_store_rejected(&fixture, "users mode 0755 must be rejected");
    require(fchmod(fixture.users_fd, 0700) == 0, "users mode must restore");

    require(fchmod(fixture.uid_fd, 0755) == 0, "UID mode must change");
    require_store_rejected(&fixture, "UID mode 0755 must be rejected");
    require(fchmod(fixture.uid_fd, 0700) == 0, "UID mode must restore");

    file_fd = openat(fixture.uid_fd, "login.conf", O_RDONLY | O_CLOEXEC);
    require(file_fd >= 0, "secret fixture must open for mode changes");
    require(fchmod(file_fd, 0644) == 0, "file mode must change to 0644");
    require_store_rejected(&fixture, "secret mode 0644 must be rejected");
    require(fchmod(file_fd, 0660) == 0, "file mode must change to 0660");
    require_store_rejected(&fixture, "secret mode 0660 must be rejected");
    require(fchmod(file_fd, 0600) == 0, "file mode must restore");
    require_wrong_ownership_rejected(&fixture, file_fd, 0,
                                     "wrong secret-file uid must be rejected");
    require_wrong_ownership_rejected(&fixture, file_fd, 1,
                                     "wrong secret-file gid must be rejected");
    require(close(file_fd) == 0, "secret fixture descriptor must close");

    fixture_destroy(&fixture);
}

static void test_store_rejects_symlinks_hardlinks_and_nonregular_objects(void)
{
    struct store_fixture fixture;
    struct sockaddr_un address;
    struct stat status;
    int socket_fd;
    const char *allow_device_skip;

    fixture_create(&fixture);
    fixture_write_valid_file(&fixture, "login.conf");
    require(renameat(fixture.root_fd, "users", fixture.root_fd,
                     "users.real") == 0,
            "users directory must move for symlink test");
    require(symlinkat("users.real", fixture.root_fd, "users") == 0,
            "users symlink must be created");
    require_store_rejected(&fixture, "users symlink must be rejected");
    require(unlinkat(fixture.root_fd, "users", 0) == 0,
            "users symlink must be removed");
    require(renameat(fixture.root_fd, "users.real", fixture.root_fd,
                     "users") == 0,
            "users directory must restore");

    require(renameat(fixture.users_fd, "1000", fixture.users_fd,
                     "1000.real") == 0,
            "UID directory must move for symlink test");
    require(symlinkat("1000.real", fixture.users_fd, "1000") == 0,
            "UID symlink must be created");
    require_store_rejected(&fixture, "UID symlink must be rejected");
    require(unlinkat(fixture.users_fd, "1000", 0) == 0,
            "UID symlink must be removed");
    require(renameat(fixture.users_fd, "1000.real", fixture.users_fd,
                     "1000") == 0,
            "UID directory must restore");

    require(renameat(fixture.uid_fd, "login.conf", fixture.uid_fd,
                     "other.conf") == 0,
            "secret file must move for symlink test");
    require(symlinkat("other.conf", fixture.uid_fd, "login.conf") == 0,
            "secret symlink must be created");
    require_store_rejected(&fixture, "secret symlink must be rejected");
    require(unlinkat(fixture.uid_fd, "login.conf", 0) == 0,
            "secret symlink must be removed");
    require(renameat(fixture.uid_fd, "other.conf", fixture.uid_fd,
                     "login.conf") == 0,
            "secret file must restore");

    require(linkat(fixture.uid_fd, "login.conf", fixture.uid_fd,
                   "other.conf", 0) == 0,
            "hard link fixture must be created");
    require_store_rejected(&fixture, "hard-linked secret must be rejected");
    require(unlinkat(fixture.uid_fd, "other.conf", 0) == 0,
            "hard link fixture must be removed");

    require(unlinkat(fixture.uid_fd, "login.conf", 0) == 0,
            "regular secret must be removed for FIFO test");
    require(mkfifoat(fixture.uid_fd, "login.conf", 0600) == 0,
            "FIFO fixture must be created");
    require_store_rejected(&fixture, "FIFO secret must be rejected");
    require(unlinkat(fixture.uid_fd, "login.conf", 0) == 0,
            "FIFO fixture must be removed");

    socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(socket_fd >= 0, "UNIX socket fixture must be created");
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    require(snprintf(address.sun_path, sizeof(address.sun_path),
                     "%s/users/1000/login.conf", fixture.root_path) > 0,
            "UNIX socket path must format");
    if (bind(socket_fd, (const struct sockaddr *)&address, sizeof(address)) !=
        0) {
        perror("UNIX socket fixture bind");
        require(0, "UNIX socket fixture must bind");
    }
    require_store_rejected(&fixture, "socket secret must be rejected");
    require(close(socket_fd) == 0, "UNIX socket fixture must close");
    require(unlinkat(fixture.uid_fd, "login.conf", 0) == 0,
            "UNIX socket fixture must be removed");

    allow_device_skip = getenv("OCRA_TEST_ALLOW_MKNOD_SKIP");
    if (mknodat(fixture.uid_fd, "login.conf", S_IFCHR | 0600,
                makedev(1U, 3U)) != 0) {
        if ((errno == EPERM || errno == EACCES) && allow_device_skip != NULL &&
            strcmp(allow_device_skip, "yes") == 0) {
            (void)fprintf(stderr,
                          "SKIP: real device node requires CAP_MKNOD\n");
            fixture_destroy(&fixture);
            return;
        }
        perror("real device fixture mknodat");
        require(0, "real device node must be created in temporary tree");
    }
    require(fstatat(fixture.uid_fd, "login.conf", &status,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
                S_ISCHR(status.st_mode) && major(status.st_rdev) == 1U &&
                minor(status.st_rdev) == 3U,
            "fixture must be a real character-device inode");
    require_store_rejected(&fixture, "real device secret must be rejected");
    require(unlinkat(fixture.uid_fd, "login.conf", 0) == 0,
            "real device fixture must be removed");

    fixture_destroy(&fixture);
}

static void test_store_uses_open_descriptor_and_detects_inode_mutation(void)
{
    struct store_fixture fixture;
    struct mutation_context context;
    struct ocra_secret_record record;

    fixture_create(&fixture);
    fixture_write_valid_file(&fixture, "login.conf");
    context.uid_fd = fixture.uid_fd;
    context.replace_path = 0;
    ocra_secret_store_set_after_open_hook_for_tests(mutate_secret_after_open,
                                                    &context);
    require_store_rejected(&fixture,
                           "same-inode mutation after open must be rejected");
    ocra_secret_store_reset_after_open_hook_for_tests();

    require(unlinkat(fixture.uid_fd, "login.conf", 0) == 0,
            "mutated fixture must be removed");
    fixture_write_valid_file(&fixture, "login.conf");
    context.replace_path = 1;
    ocra_secret_store_set_after_open_hook_for_tests(mutate_secret_after_open,
                                                    &context);
    memset(&record, 0xa5, sizeof(record));
    if (ocra_secret_store_load_at(fixture.root_fd, "1000", "login",
                                  &record) == 0) {
        require(strcmp(record.key_id, "0123456789abcdef") == 0,
                "path replacement must return only the opened record");
    } else {
        require(memory_is_zero(&record, sizeof(record)),
                "path replacement denial must clear the complete record");
    }
    ocra_secret_store_reset_after_open_hook_for_tests();

    require(unlinkat(fixture.uid_fd, "login.conf", 0) == 0,
            "replacement fixture must be removed");
    require(renameat(fixture.uid_fd, "other.conf", fixture.uid_fd,
                     "login.conf") == 0,
            "original fixture path must restore");
    fixture_destroy(&fixture);
}

static void test_store_rejects_manipulated_scope_and_file_size_boundaries(void)
{
    struct store_fixture fixture;
    struct ocra_secret_record record;
    unsigned char oversized[OCRA_SECRET_FILE_MAX + 1U];
    unsigned char long_line[OCRA_SECRET_LINE_MAX + 2U];

    fixture_create(&fixture);
    fixture_write_valid_file(&fixture, "login.conf");

    memset(&record, 0xa5, sizeof(record));
    require(ocra_secret_store_load_at(fixture.root_fd, "00", "login",
                                      &record) != 0,
            "noncanonical UID path must be rejected");
    require(memory_is_zero(&record, sizeof(record)),
            "invalid UID must clear output");
    memset(&record, 0xa5, sizeof(record));
    require(ocra_secret_store_load_at(fixture.root_fd, "4294967296", "login",
                                      &record) != 0,
            "out-of-range UID path must be rejected");
    require(memory_is_zero(&record, sizeof(record)),
            "out-of-range UID must clear output");
    memset(&record, 0xa5, sizeof(record));
    require(ocra_secret_store_load_at(fixture.root_fd, "1000", "../login",
                                      &record) != 0,
            "traversal service must be rejected");
    require(memory_is_zero(&record, sizeof(record)),
            "traversal service must clear output");
    memset(&record, 0xa5, sizeof(record));
    require(ocra_secret_store_load_at(fixture.root_fd, "1000", "a/b",
                                      &record) != 0,
            "slash service must be rejected");
    require(memory_is_zero(&record, sizeof(record)),
            "slash service must clear output");

    require(unlinkat(fixture.uid_fd, "login.conf", 0) == 0,
            "valid fixture must be removed for size tests");
    fixture_write_bytes(&fixture, (const unsigned char *)"", 0U);
    require_store_rejected(&fixture, "empty secret file must be rejected");
    require(unlinkat(fixture.uid_fd, "login.conf", 0) == 0,
            "empty fixture must be removed");

    memset(oversized, 'x', sizeof(oversized));
    fixture_write_bytes(&fixture, oversized, sizeof(oversized));
    require_store_rejected(&fixture, "oversized secret file must be rejected");
    require(unlinkat(fixture.uid_fd, "login.conf", 0) == 0,
            "oversized fixture must be removed");

    memset(long_line, 'x', sizeof(long_line));
    long_line[sizeof(long_line) - 1U] = '\n';
    fixture_write_bytes(&fixture, long_line, sizeof(long_line));
    require_store_rejected(&fixture, "overlong file line must be rejected");

    fixture_destroy(&fixture);
}

int main(void)
{
    test_scope_accepts_only_canonical_uid_and_safe_service();
    test_parser_decodes_complete_valid_record();
    test_parser_rejects_malformed_structure_and_clears_output();
    test_parser_decodes_nonzero_canonical_base32();
    test_parser_rejects_invalid_field_values();
    test_store_loads_valid_file_and_fails_closed_when_absent();
    test_store_requires_exact_modes_and_expected_ownership();
    test_store_rejects_symlinks_hardlinks_and_nonregular_objects();
    test_store_uses_open_descriptor_and_detects_inode_mutation();
    test_store_rejects_manipulated_scope_and_file_size_boundaries();
    return EXIT_SUCCESS;
}
