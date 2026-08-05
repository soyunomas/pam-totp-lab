#define _GNU_SOURCE

#include "secret_store.h"

#include "secure_memory.h"
#include "scope.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef OCRA_TESTING
static ocra_secret_store_stat_provider test_stat_provider = fstat;
static ocra_secret_store_after_open_hook test_after_open_hook;
static void *test_after_open_context;
#endif

static int ocra_fstat(int fd, struct stat *status)
{
#ifdef OCRA_TESTING
    return test_stat_provider(fd, status);
#else
    return fstat(fd, status);
#endif
}

static uid_t ocra_expected_uid(void)
{
#ifdef OCRA_TESTING
    return geteuid();
#else
    return (uid_t)0;
#endif
}

static gid_t ocra_expected_gid(void)
{
#ifdef OCRA_TESTING
    return getegid();
#else
    return (gid_t)0;
#endif
}

static int ocra_validate_directory_fd(int fd)
{
    struct stat status;

    return ocra_fstat(fd, &status) == 0 && S_ISDIR(status.st_mode) &&
           (status.st_mode & 07777) == 0700 &&
           status.st_uid == ocra_expected_uid() &&
           status.st_gid == ocra_expected_gid()
               ? 0
               : -1;
}

static int ocra_validate_system_directory_fd(int fd)
{
    struct stat status;

    return ocra_fstat(fd, &status) == 0 && S_ISDIR(status.st_mode) &&
           status.st_uid == (uid_t)0 && status.st_gid == (gid_t)0 &&
           (status.st_mode & 0022) == 0
               ? 0
               : -1;
}

static int ocra_validate_file_metadata(int fd, struct stat *status)
{
    if (ocra_fstat(fd, status) != 0 || !S_ISREG(status->st_mode) ||
        status->st_nlink != 1 ||
        (status->st_mode & 07777) != 0600 ||
        status->st_uid != ocra_expected_uid() ||
        status->st_gid != ocra_expected_gid()) {
        return -1;
    }
    return 0;
}

static int ocra_file_metadata_unchanged(const struct stat *before,
                                        const struct stat *after)
{
    return before->st_dev == after->st_dev &&
           before->st_ino == after->st_ino &&
           before->st_mode == after->st_mode &&
           before->st_nlink == after->st_nlink &&
           before->st_uid == after->st_uid && before->st_gid == after->st_gid &&
           before->st_size == after->st_size &&
           before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
           before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
           before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
           before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
}

static void ocra_run_after_open_hook(int file_fd)
{
#ifdef OCRA_TESTING
    if (test_after_open_hook != NULL) {
        test_after_open_hook(file_fd, test_after_open_context);
    }
#else
    (void)file_fd;
#endif
}

#define FIELD_VERSION (1U << 0)
#define FIELD_SUITE (1U << 1)
#define FIELD_KEY_ID (1U << 2)
#define FIELD_SECRET (1U << 3)
#define FIELD_ENABLED (1U << 4)
#define FIELD_ALL                                                            \
    (FIELD_VERSION | FIELD_SUITE | FIELD_KEY_ID | FIELD_SECRET | FIELD_ENABLED)

static unsigned int ocra_field_for_line(const unsigned char *line,
                                        size_t length)
{
    static const struct {
        const char *name;
        size_t length;
        unsigned int field;
    } fields[] = {{"version", 7U, FIELD_VERSION},
                  {"suite", 5U, FIELD_SUITE},
                  {"key_id", 6U, FIELD_KEY_ID},
                  {"secret", 6U, FIELD_SECRET},
                  {"enabled", 7U, FIELD_ENABLED}};
    size_t index;

    for (index = 0U; index < sizeof(fields) / sizeof(fields[0]); ++index) {
        if (length > fields[index].length &&
            line[fields[index].length] == (unsigned char)'=' &&
            memcmp(line, fields[index].name, fields[index].length) == 0) {
            return fields[index].field;
        }
    }
    return 0U;
}

static size_t ocra_field_name_length(unsigned int field)
{
    switch (field) {
    case FIELD_VERSION:
        return 7U;
    case FIELD_SUITE:
        return 5U;
    case FIELD_KEY_ID:
    case FIELD_SECRET:
        return 6U;
    case FIELD_ENABLED:
        return 7U;
    default:
        return 0U;
    }
}

static int ocra_base32_value(unsigned char byte, unsigned int *value)
{
    if (byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') {
        *value = (unsigned int)(byte - (unsigned char)'A');
        return 0;
    }
    if (byte >= (unsigned char)'2' && byte <= (unsigned char)'7') {
        *value = 26U + (unsigned int)(byte - (unsigned char)'2');
        return 0;
    }
    return -1;
}

static int ocra_decode_secret(const unsigned char *encoded, size_t length,
                              unsigned char output[OCRA_SECRET_BYTES])
{
    unsigned char decoded[OCRA_SECRET_BYTES];
    unsigned int accumulator = 0U;
    unsigned int bits = 0U;
    unsigned int value = 0U;
    size_t input_index;
    size_t output_index = 0U;
    int result = -1;

    memset(decoded, 0, sizeof(decoded));
    if (length != 52U) {
        goto cleanup;
    }
    for (input_index = 0U; input_index < length; ++input_index) {
        if (ocra_base32_value(encoded[input_index], &value) != 0) {
            goto cleanup;
        }
        accumulator = (accumulator << 5U) | value;
        bits += 5U;
        if (bits >= 8U) {
            bits -= 8U;
            if (output_index >= OCRA_SECRET_BYTES) {
                goto cleanup;
            }
            decoded[output_index++] =
                (unsigned char)((accumulator >> bits) & 0xffU);
            accumulator &= bits == 0U ? 0U : ((1U << bits) - 1U);
        }
    }
    if (output_index != OCRA_SECRET_BYTES || bits != 4U ||
        accumulator != 0U) {
        goto cleanup;
    }
    memcpy(output, decoded, sizeof(decoded));
    result = 0;

cleanup:
    secure_memory_clear(decoded, sizeof(decoded));
    secure_memory_clear(&accumulator, sizeof(accumulator));
    secure_memory_clear(&value, sizeof(value));
    return result;
}

static int ocra_value_equals(const unsigned char *value, size_t length,
                             const char *expected)
{
    size_t expected_length = strlen(expected);

    return length == expected_length &&
           memcmp(value, expected, expected_length) == 0;
}

static int ocra_key_id_is_valid(const unsigned char *value, size_t length)
{
    size_t index;

    if (length != OCRA_KEY_ID_HEX_LENGTH) {
        return 0;
    }
    for (index = 0U; index < length; ++index) {
        unsigned char byte = value[index];

        if (!((byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              (byte >= (unsigned char)'a' && byte <= (unsigned char)'f') ||
              (byte >= (unsigned char)'A' && byte <= (unsigned char)'F'))) {
            return 0;
        }
    }
    return 1;
}

static int ocra_parse_record(const unsigned char *data, size_t length,
                             struct ocra_secret_record *record)
{
    static const unsigned int field_order[] = {
        FIELD_VERSION, FIELD_SUITE, FIELD_KEY_ID, FIELD_SECRET, FIELD_ENABLED};
    unsigned int seen = 0U;
    const unsigned char *version_value = NULL;
    size_t version_length = 0U;
    const unsigned char *suite_value = NULL;
    size_t suite_length = 0U;
    const unsigned char *key_id_value = NULL;
    size_t key_id_length = 0U;
    const unsigned char *secret_value = NULL;
    size_t secret_length = 0U;
    const unsigned char *enabled_value = NULL;
    size_t enabled_length = 0U;
    size_t line_start = 0U;
    size_t line_count = 0U;
    size_t index;

    ocra_secret_record_clear(record);
    if (data == NULL || record == NULL || length == 0U ||
        length > OCRA_SECRET_FILE_MAX || data[length - 1U] != '\n') {
        return -1;
    }
    for (index = 0U; index < length; ++index) {
        size_t line_length;
        unsigned int field;
        size_t name_length;

        if (data[index] == '\0' || data[index] == '\r') {
            return -1;
        }
        if (data[index] != '\n') {
            if (index - line_start >= OCRA_SECRET_LINE_MAX) {
                return -1;
            }
            continue;
        }
        line_length = index - line_start;
        if (line_length == 0U || line_length > OCRA_SECRET_LINE_MAX) {
            return -1;
        }
        field = ocra_field_for_line(data + line_start, line_length);
        if (field == 0U || (seen & field) != 0U ||
            line_count >= sizeof(field_order) / sizeof(field_order[0]) ||
            field != field_order[line_count]) {
            return -1;
        }
        ++line_count;
        seen |= field;
        name_length = ocra_field_name_length(field);
        if (field == FIELD_VERSION) {
            version_value = data + line_start + name_length + 1U;
            version_length = line_length - name_length - 1U;
        } else if (field == FIELD_SUITE) {
            suite_value = data + line_start + name_length + 1U;
            suite_length = line_length - name_length - 1U;
        } else if (field == FIELD_KEY_ID) {
            key_id_value = data + line_start + name_length + 1U;
            key_id_length = line_length - name_length - 1U;
        } else if (field == FIELD_SECRET) {
            secret_value = data + line_start + name_length + 1U;
            secret_length = line_length - name_length - 1U;
        } else if (field == FIELD_ENABLED) {
            enabled_value = data + line_start + name_length + 1U;
            enabled_length = line_length - name_length - 1U;
        }
        line_start = index + 1U;
    }
    if (seen != FIELD_ALL ||
        line_count != sizeof(field_order) / sizeof(field_order[0])) {
        return -1;
    }
    if (version_value == NULL || suite_value == NULL || key_id_value == NULL ||
        secret_value == NULL || enabled_value == NULL ||
        !ocra_value_equals(version_value, version_length, "1") ||
        !ocra_value_equals(suite_value, suite_length,
                           "OCRA-1:HOTP-SHA256-8:QN10") ||
        !ocra_key_id_is_valid(key_id_value, key_id_length) ||
        !ocra_value_equals(enabled_value, enabled_length, "yes") ||
        ocra_decode_secret(secret_value, secret_length, record->secret) != 0) {
        ocra_secret_record_clear(record);
        return -1;
    }
    memcpy(record->key_id, key_id_value, OCRA_KEY_ID_HEX_LENGTH);
    record->key_id[OCRA_KEY_ID_HEX_LENGTH] = '\0';
    return 0;
}

void ocra_secret_record_clear(struct ocra_secret_record *record)
{
    if (record != NULL) {
        secure_memory_clear(record, sizeof(*record));
    }
}

int ocra_secret_store_load(uid_t uid, const char *service,
                           struct ocra_secret_record *record)
{
    char uid_text[OCRA_UID_TEXT_MAX_LENGTH + 1U];
    int root_fd = -1;
    int etc_fd = -1;
    int security_fd = -1;
    int store_fd = -1;
    int result = -1;
    int formatted;

    ocra_secret_record_clear(record);
    formatted = snprintf(uid_text, sizeof(uid_text), "%" PRIuMAX,
                         (uintmax_t)uid);
    if (record == NULL || formatted < 0 ||
        (size_t)formatted >= sizeof(uid_text)) {
        goto cleanup;
    }
    root_fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root_fd < 0 || ocra_validate_system_directory_fd(root_fd) != 0) {
        goto cleanup;
    }
    etc_fd = openat(root_fd, "etc",
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (etc_fd < 0 || ocra_validate_system_directory_fd(etc_fd) != 0) {
        goto cleanup;
    }
    security_fd = openat(etc_fd, "security",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (security_fd < 0 ||
        ocra_validate_system_directory_fd(security_fd) != 0) {
        goto cleanup;
    }
    store_fd = openat(security_fd, "pam-ocra",
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (store_fd < 0) {
        goto cleanup;
    }
    result = ocra_secret_store_load_at(store_fd, uid_text, service, record);

cleanup:
    if (store_fd >= 0) {
        (void)close(store_fd);
    }
    if (security_fd >= 0) {
        (void)close(security_fd);
    }
    if (etc_fd >= 0) {
        (void)close(etc_fd);
    }
    if (root_fd >= 0) {
        (void)close(root_fd);
    }
    secure_memory_clear(uid_text, sizeof(uid_text));
    if (result != 0) {
        ocra_secret_record_clear(record);
    }
    return result;
}

int ocra_secret_store_load_at(int root_fd, const char *uid_text,
                              const char *service,
                              struct ocra_secret_record *record)
{
    unsigned char buffer[OCRA_SECRET_FILE_MAX + 1U];
    char file_name[OCRA_SERVICE_MAX_LENGTH + sizeof(".conf")];
    uid_t parsed_uid;
    size_t length = 0U;
    int users_fd = -1;
    int uid_fd = -1;
    int file_fd = -1;
    int result = -1;
    struct stat initial_status;
    struct stat final_status;

    ocra_secret_record_clear(record);
    memset(buffer, 0, sizeof(buffer));
    if (record == NULL || root_fd < 0 ||
        ocra_scope_parse_uid(uid_text, &parsed_uid) != 0 ||
        ocra_scope_validate_service(service) != 0 ||
        snprintf(file_name, sizeof(file_name), "%s.conf", service) < 0) {
        goto cleanup;
    }
    (void)parsed_uid;
    if (ocra_validate_directory_fd(root_fd) != 0) {
        goto cleanup;
    }
    users_fd = openat(root_fd, "users",
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (users_fd < 0) {
        goto cleanup;
    }
    if (ocra_validate_directory_fd(users_fd) != 0) {
        goto cleanup;
    }
    uid_fd = openat(users_fd, uid_text,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (uid_fd < 0) {
        goto cleanup;
    }
    if (ocra_validate_directory_fd(uid_fd) != 0) {
        goto cleanup;
    }
    file_fd = openat(uid_fd, file_name,
                     O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (file_fd < 0) {
        goto cleanup;
    }
    if (ocra_validate_file_metadata(file_fd, &initial_status) != 0) {
        goto cleanup;
    }
    ocra_run_after_open_hook(file_fd);
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
    if (ocra_validate_file_metadata(file_fd, &final_status) != 0 ||
        !ocra_file_metadata_unchanged(&initial_status, &final_status) ||
        length > OCRA_SECRET_FILE_MAX ||
        ocra_parse_record(buffer, length, record) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (file_fd >= 0) {
        (void)close(file_fd);
    }
    if (uid_fd >= 0) {
        (void)close(uid_fd);
    }
    if (users_fd >= 0) {
        (void)close(users_fd);
    }
    secure_memory_clear(buffer, sizeof(buffer));
    if (result != 0) {
        ocra_secret_record_clear(record);
    }
    return result;
}

#ifdef OCRA_TESTING
int ocra_secret_store_parse_for_tests(const unsigned char *data, size_t length,
                                      struct ocra_secret_record *record)
{
    return ocra_parse_record(data, length, record);
}

void ocra_secret_store_set_after_open_hook_for_tests(
    ocra_secret_store_after_open_hook hook, void *context)
{
    test_after_open_hook = hook;
    test_after_open_context = context;
}

void ocra_secret_store_reset_after_open_hook_for_tests(void)
{
    test_after_open_hook = NULL;
    test_after_open_context = NULL;
}

void ocra_secret_store_set_stat_provider_for_tests(
    ocra_secret_store_stat_provider provider)
{
    test_stat_provider = provider == NULL ? fstat : provider;
}

void ocra_secret_store_reset_stat_provider_for_tests(void)
{
    test_stat_provider = fstat;
}
#endif
