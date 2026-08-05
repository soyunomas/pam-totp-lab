#define _GNU_SOURCE

#include "ocra_enroll.h"

#include "../scope.h"
#include "../challenge.h"
#include "../ocra_core.h"
#include "../rate_limit.h"
#include "../secret_store.h"
#include "../secure_memory.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>

#define OCRA_RECORD_CAPACITY 256U
#define OCRA_KEY_ID_RANDOM_BYTES 8U
#define OCRA_TRANSACTION_ID_BYTES 8U
#define OCRA_JOURNAL_CAPACITY (PATH_MAX * 2U + 2048U)
#define OCRA_ADMIN_JOURNAL_NAME "admin.txn"

struct enroll_target {
    int directory_fd;
    dev_t device;
    ino_t inode;
    char name[NAME_MAX + 1U];
    char path[PATH_MAX];
};

#ifdef OCRA_TESTING
static ocra_enroll_random_provider test_random_provider;
static ocra_enroll_user_provider test_user_provider;
static uid_t test_euid;
static int test_euid_is_set;
static enum ocra_enroll_fault_operation test_fault_operation;
static unsigned int test_fault_occurrence;
static unsigned int test_fault_seen;
#endif

static int inject_fault(enum ocra_enroll_fault_operation operation)
{
#ifdef OCRA_TESTING
    if (test_fault_operation == operation) {
        ++test_fault_seen;
        if (test_fault_seen == test_fault_occurrence) {
            errno = EIO;
            return 1;
        }
    }
#else
    (void)operation;
#endif
    return 0;
}

static uid_t enroll_euid(void)
{
#ifdef OCRA_TESTING
    if (test_euid_is_set != 0) {
        return test_euid;
    }
#endif
    return geteuid();
}

static uid_t server_owner_uid(void)
{
#ifdef OCRA_TESTING
    return geteuid();
#else
    return (uid_t)0;
#endif
}

static gid_t server_owner_gid(void)
{
#ifdef OCRA_TESTING
    return getegid();
#else
    return (gid_t)0;
#endif
}

static int system_random(void *buffer, size_t length)
{
    unsigned char *bytes = buffer;
    size_t offset = 0U;

    while (offset < length) {
        ssize_t count = getrandom(bytes + offset, length - offset, 0U);

        if (count > 0) {
            offset += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int enroll_random(void *buffer, size_t length)
{
#ifdef OCRA_TESTING
    if (test_random_provider != NULL) {
        return test_random_provider(buffer, length);
    }
#endif
    return system_random(buffer, length);
}

static int system_resolve_user(const char *name, uid_t *uid, gid_t *gid)
{
    struct passwd password;
    struct passwd *result = NULL;
    long suggested = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t capacity = suggested > 0L ? (size_t)suggested : 16384U;
    char *buffer;
    int status;

    if (name == NULL || uid == NULL || gid == NULL || capacity > 1048576U) {
        return -1;
    }
    buffer = malloc(capacity);
    if (buffer == NULL) {
        return -1;
    }
    status = getpwnam_r(name, &password, buffer, capacity, &result);
    if (status == 0 && result != NULL) {
        *uid = result->pw_uid;
        *gid = result->pw_gid;
        status = 0;
    } else {
        status = -1;
    }
    secure_memory_clear(buffer, capacity);
    free(buffer);
    return status;
}

static int enroll_resolve_user(const char *name, uid_t *uid, gid_t *gid)
{
#ifdef OCRA_TESTING
    if (test_user_provider != NULL) {
        return test_user_provider(name, uid, gid);
    }
#endif
    return system_resolve_user(name, uid, gid);
}

static int metadata_is_directory(int fd, uid_t uid, gid_t gid,
                                 int exact_mode)
{
    struct stat status;

    if (fstat(fd, &status) != 0 || !S_ISDIR(status.st_mode) ||
        status.st_uid != uid || status.st_gid != gid) {
        return 0;
    }
    if (exact_mode != 0) {
        return (status.st_mode & 07777) == 0700;
    }
    return (status.st_mode & 0022) == 0;
}

static int metadata_is_file(int fd, uid_t uid, gid_t gid)
{
    struct stat status;

    return fstat(fd, &status) == 0 && S_ISREG(status.st_mode) &&
           status.st_nlink == 1 && (status.st_mode & 07777) == 0600 &&
           status.st_uid == uid && status.st_gid == gid;
}

static int path_matches_fd(int directory_fd, const char *name, int fd)
{
    struct stat path_status;
    struct stat fd_status;

    return fstat(fd, &fd_status) == 0 &&
           fstatat(directory_fd, name, &path_status, AT_SYMLINK_NOFOLLOW) == 0 &&
           path_status.st_dev == fd_status.st_dev &&
           path_status.st_ino == fd_status.st_ino &&
           S_ISREG(path_status.st_mode);
}

static int normalize_created(int fd, mode_t mode, uid_t uid, gid_t gid)
{
    return fchmod(fd, mode) == 0 && fchown(fd, uid, gid) == 0 ? 0 : -1;
}

static int open_or_create_server_directory(int parent_fd, const char *name)
{
    uid_t uid = server_owner_uid();
    gid_t gid = server_owner_gid();
    int created = 0;
    int fd;

    if (mkdirat(parent_fd, name, 0700) == 0) {
        created = 1;
    } else if (errno != EEXIST) {
        return -1;
    }
    fd = openat(parent_fd, name,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 ||
        (created != 0 && normalize_created(fd, 0700, uid, gid) != 0) ||
        !metadata_is_directory(fd, uid, gid, 1)) {
        if (fd >= 0) {
            (void)close(fd);
        }
        return -1;
    }
    return fd;
}

static int open_admin_lock(int root_fd)
{
    static const char lock_name[] = "admin.lock";
    struct stat status;
    int created = 0;
    int fd = -1;
    unsigned int attempt;

    if (!metadata_is_directory(root_fd, server_owner_uid(),
                               server_owner_gid(), 1)) {
        return -1;
    }
    for (attempt = 0U; attempt < 3U && fd < 0; ++attempt) {
        if (fstatat(root_fd, lock_name, &status, AT_SYMLINK_NOFOLLOW) == 0) {
            if (!S_ISREG(status.st_mode)) {
                return -1;
            }
            fd = openat(root_fd, lock_name,
                        O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
            if (fd < 0) {
                return -1;
            }
            break;
        }
        if (errno != ENOENT) {
            return -1;
        }
        fd = openat(root_fd, lock_name,
                    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
        if (fd < 0 && errno == EEXIST) {
            continue;
        }
        if (fd < 0) {
            return -1;
        }
        created = 1;
        if (flock(fd, LOCK_EX) != 0 ||
            normalize_created(fd, 0600, server_owner_uid(),
                              server_owner_gid()) != 0 ||
            fsync(fd) != 0 || fsync(root_fd) != 0) {
            (void)close(fd);
            return -1;
        }
    }
    if (fd < 0) {
        return -1;
    }
    if (!metadata_is_file(fd, server_owner_uid(), server_owner_gid()) ||
        !path_matches_fd(root_fd, lock_name, fd) ||
        (created == 0 && flock(fd, LOCK_EX) != 0) ||
        !metadata_is_file(fd, server_owner_uid(), server_owner_gid()) ||
        !path_matches_fd(root_fd, lock_name, fd)) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

static int open_server_scope(int root_fd, const char *uid_text)
{
    int users_fd = -1;
    int uid_fd = -1;

    if (!metadata_is_directory(root_fd, server_owner_uid(),
                               server_owner_gid(), 1)) {
        return -1;
    }
    users_fd = open_or_create_server_directory(root_fd, "users");
    if (users_fd < 0) {
        return -1;
    }
    uid_fd = open_or_create_server_directory(users_fd, uid_text);
    (void)close(users_fd);
    return uid_fd;
}

static int open_existing_server_scope(int root_fd, const char *uid_text)
{
    int users_fd = -1;
    int uid_fd = -1;

    if (!metadata_is_directory(root_fd, server_owner_uid(),
                               server_owner_gid(), 1)) {
        return -1;
    }
    users_fd = openat(root_fd, "users",
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (users_fd < 0 ||
        !metadata_is_directory(users_fd, server_owner_uid(),
                               server_owner_gid(), 1)) {
        goto cleanup;
    }
    uid_fd = openat(users_fd, uid_text,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (uid_fd < 0 ||
        !metadata_is_directory(uid_fd, server_owner_uid(), server_owner_gid(),
                               1)) {
        if (uid_fd >= 0) {
            (void)close(uid_fd);
        }
        uid_fd = -1;
    }

cleanup:
    if (users_fd >= 0) {
        (void)close(users_fd);
    }
    return uid_fd;
}

static int component_is_safe(const char *component, size_t length)
{
    return length > 0U && length <= NAME_MAX &&
           !(length == 1U && component[0] == '.') &&
           !(length == 2U && component[0] == '.' && component[1] == '.');
}

static int open_client_target(const char *path, uid_t uid, gid_t gid,
                              struct enroll_target *target)
{
    const char *cursor;
    int directory_fd = -1;

    if (path == NULL || target == NULL || path[0] != '/') {
        return -1;
    }
    target->directory_fd = -1;
    target->device = (dev_t)0;
    target->inode = (ino_t)0;
    target->name[0] = '\0';
    target->path[0] = '\0';
    if (strlen(path) >= sizeof(target->path)) {
        return -1;
    }
    directory_fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0) {
        return -1;
    }
    cursor = path + 1;
    for (;;) {
        char component[NAME_MAX + 1U];
        const char *start;
        size_t length;
        int next_fd;

        while (*cursor == '/') {
            ++cursor;
        }
        start = cursor;
        while (*cursor != '\0' && *cursor != '/') {
            ++cursor;
        }
        length = (size_t)(cursor - start);
        if (!component_is_safe(start, length)) {
            goto fail;
        }
        (void)memcpy(component, start, length);
        component[length] = '\0';
        while (*cursor == '/') {
            ++cursor;
        }
        if (*cursor == '\0') {
            (void)memcpy(target->name, start, length);
            target->name[length] = '\0';
            break;
        }
        next_fd = openat(directory_fd, component,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next_fd < 0) {
            goto fail;
        }
        (void)close(directory_fd);
        directory_fd = next_fd;
    }
    if (!metadata_is_directory(directory_fd, uid, gid, 0)) {
        goto fail;
    }
    {
        struct stat status;

        if (fstat(directory_fd, &status) != 0) {
            goto fail;
        }
        target->device = status.st_dev;
        target->inode = status.st_ino;
    }
    (void)strcpy(target->path, path);
    target->directory_fd = directory_fd;
    return 0;

fail:
    (void)close(directory_fd);
    return -1;
}

static int target_is_absent(int directory_fd, const char *name)
{
    struct stat status;

    if (fstatat(directory_fd, name, &status, AT_SYMLINK_NOFOLLOW) == 0) {
        return 0;
    }
    return errno == ENOENT;
}

static int system_write_complete(int fd, const unsigned char *data,
                                 size_t length)
{
    size_t offset = 0U;

    while (offset < length) {
        ssize_t count = write(fd, data + offset, length - offset);

        if (count > 0) {
            offset += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int enroll_write_complete(int fd, const unsigned char *data,
                                 size_t length)
{
    if (inject_fault(OCRA_ENROLL_FAULT_WRITE_PARTIAL) != 0) {
        size_t partial = length / 2U;

        if (partial > 0U && system_write_complete(fd, data, partial) != 0) {
            return -1;
        }
        errno = EIO;
        return -1;
    }
    return system_write_complete(fd, data, length);
}

static int enroll_fsync_file(int fd)
{
    return inject_fault(OCRA_ENROLL_FAULT_FSYNC_FILE) != 0 ? -1 : fsync(fd);
}

static int enroll_fsync_directory(int fd)
{
    return inject_fault(OCRA_ENROLL_FAULT_FSYNC_DIRECTORY) != 0 ? -1
                                                                : fsync(fd);
}

static int enroll_rename(int old_directory_fd, const char *old_name,
                         int new_directory_fd, const char *new_name)
{
    return inject_fault(OCRA_ENROLL_FAULT_RENAME) != 0
               ? -1
               : renameat(old_directory_fd, old_name, new_directory_fd,
                          new_name);
}

static int stage_record(int directory_fd, const char *name, uid_t uid,
                        gid_t gid, const unsigned char *record,
                        size_t record_length)
{
    int fd = openat(directory_fd, name,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
    int result = -1;

    if (fd < 0) {
        return -1;
    }
    if (normalize_created(fd, 0600, uid, gid) == 0 &&
        metadata_is_file(fd, uid, gid) &&
        path_matches_fd(directory_fd, name, fd) &&
        enroll_write_complete(fd, record, record_length) == 0 &&
        enroll_fsync_file(fd) == 0) {
        result = 0;
    }
    if (close(fd) != 0) {
        result = -1;
    }
    if (result == 0 && enroll_fsync_directory(directory_fd) != 0) {
        result = -1;
    }
    if (result != 0) {
        (void)unlinkat(directory_fd, name, 0);
        (void)fsync(directory_fd);
    }
    return result;
}

static void encode_base32(const unsigned char input[OCRA_SECRET_BYTES],
                          char output[53U])
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    uint32_t accumulator = 0U;
    unsigned int bits = 0U;
    size_t input_index;
    size_t output_index = 0U;

    for (input_index = 0U; input_index < OCRA_SECRET_BYTES; ++input_index) {
        accumulator = (accumulator << 8U) | input[input_index];
        bits += 8U;
        while (bits >= 5U) {
            bits -= 5U;
            output[output_index++] =
                alphabet[(accumulator >> bits) & UINT32_C(31)];
        }
        accumulator &= bits == 0U ? 0U : (UINT32_C(1) << bits) - 1U;
    }
    if (bits != 0U) {
        output[output_index++] =
            alphabet[(accumulator << (5U - bits)) & UINT32_C(31)];
    }
    output[output_index] = '\0';
    secure_memory_clear(&accumulator, sizeof(accumulator));
}

static void encode_key_id(const unsigned char input[OCRA_KEY_ID_RANDOM_BYTES],
                          char output[OCRA_KEY_ID_HEX_LENGTH + 1U])
{
    static const char hexadecimal[] = "0123456789abcdef";
    size_t index;

    for (index = 0U; index < OCRA_KEY_ID_RANDOM_BYTES; ++index) {
        output[index * 2U] = hexadecimal[input[index] >> 4U];
        output[(index * 2U) + 1U] = hexadecimal[input[index] & 0x0fU];
    }
    output[OCRA_KEY_ID_HEX_LENGTH] = '\0';
}

static int build_transaction_id(
    char output[OCRA_KEY_ID_HEX_LENGTH + 1U])
{
    unsigned char random_bytes[OCRA_TRANSACTION_ID_BYTES];
    int result = -1;

    (void)memset(random_bytes, 0, sizeof(random_bytes));
    if (enroll_random(random_bytes, sizeof(random_bytes)) == 0) {
        encode_key_id(random_bytes, output);
        result = 0;
    }
    secure_memory_clear(random_bytes, sizeof(random_bytes));
    return result;
}

static int lowercase_hex_is_valid(const char *value, size_t length)
{
    size_t index;

    if (value == NULL || strlen(value) != length) {
        return 0;
    }
    for (index = 0U; index < length; ++index) {
        if (!((value[index] >= '0' && value[index] <= '9') ||
              (value[index] >= 'a' && value[index] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int hex_encode_text(const char *input, char *output,
                           size_t output_capacity)
{
    static const char alphabet[] = "0123456789abcdef";
    size_t length;
    size_t index;

    if (input == NULL || output == NULL) {
        return -1;
    }
    length = strlen(input);
    if (length > (output_capacity - 1U) / 2U) {
        return -1;
    }
    for (index = 0U; index < length; ++index) {
        unsigned char value = (unsigned char)input[index];

        output[index * 2U] = alphabet[value >> 4U];
        output[index * 2U + 1U] = alphabet[value & 0x0fU];
    }
    output[length * 2U] = '\0';
    return 0;
}

static int hex_nibble(char value, unsigned char *nibble)
{
    if (value >= '0' && value <= '9') {
        *nibble = (unsigned char)(value - '0');
        return 0;
    }
    if (value >= 'a' && value <= 'f') {
        *nibble = (unsigned char)(value - 'a' + 10);
        return 0;
    }
    return -1;
}

static int hex_decode_text(const char *input, char *output,
                           size_t output_capacity)
{
    size_t length;
    size_t index;

    if (input == NULL || output == NULL) {
        return -1;
    }
    length = strlen(input);
    if ((length & 1U) != 0U || length / 2U >= output_capacity) {
        return -1;
    }
    for (index = 0U; index < length / 2U; ++index) {
        unsigned char high;
        unsigned char low;

        if (hex_nibble(input[index * 2U], &high) != 0 ||
            hex_nibble(input[index * 2U + 1U], &low) != 0) {
            return -1;
        }
        output[index] = (char)((high << 4U) | low);
        if (output[index] == '\0') {
            return -1;
        }
    }
    output[length / 2U] = '\0';
    return 0;
}

static const char *journal_field(char **cursor, const char *prefix)
{
    char *line;
    char *newline;
    size_t prefix_length;

    if (cursor == NULL || *cursor == NULL || prefix == NULL) {
        return NULL;
    }
    line = *cursor;
    newline = strchr(line, '\n');
    if (newline == NULL) {
        return NULL;
    }
    *newline = '\0';
    *cursor = newline + 1;
    prefix_length = strlen(prefix);
    if (strncmp(line, prefix, prefix_length) != 0) {
        return NULL;
    }
    return line + prefix_length;
}

static int read_journal_header(int server_root_fd, char operation[8U],
                               char phase[16U],
                               char transaction_id[
                                   OCRA_KEY_ID_HEX_LENGTH + 1U])
{
    char body[256U];
    int fd = -1;
    ssize_t count;
    int consumed = 0;
    int matched;
    int result = -1;

    (void)memset(body, 0, sizeof(body));
    operation[0] = '\0';
    phase[0] = '\0';
    transaction_id[0] = '\0';
    fd = openat(server_root_fd, OCRA_ADMIN_JOURNAL_NAME,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || !metadata_is_file(fd, server_owner_uid(),
                                    server_owner_gid()) ||
        !path_matches_fd(server_root_fd, OCRA_ADMIN_JOURNAL_NAME, fd)) {
        goto cleanup;
    }
    do {
        count = pread(fd, body, sizeof(body) - 1U, (off_t)0);
    } while (count < 0 && errno == EINTR);
    if (count <= 0) {
        goto cleanup;
    }
    body[count] = '\0';
    matched = sscanf(body,
                     "version=2\noperation=%7[a-z]\nphase=%15[a-z]\n"
                     "txid=%16[0-9a-f]\n%n",
                     operation, phase, transaction_id, &consumed);
    if (matched == 3 && consumed > 0 &&
        lowercase_hex_is_valid(transaction_id, OCRA_KEY_ID_HEX_LENGTH) &&
        (strcmp(operation, "add") == 0 ||
         strcmp(operation, "rotate") == 0 ||
         strcmp(operation, "revoke") == 0) &&
        (strcmp(phase, "preparing") == 0 ||
         strcmp(phase, "prepared") == 0 ||
         strcmp(phase, "committing") == 0)) {
        result = 0;
    }

cleanup:
    if (fd >= 0 && close(fd) != 0) {
        result = -1;
    }
    secure_memory_clear(body, sizeof(body));
    if (result != 0) {
        secure_memory_clear(operation, 8U);
        secure_memory_clear(phase, 16U);
        secure_memory_clear(transaction_id,
                            OCRA_KEY_ID_HEX_LENGTH + 1U);
    }
    return result;
}

static int journal_identity_matches(int server_root_fd, const char *operation,
                                    const char *transaction_id)
{
    char actual_operation[8U];
    char phase[16U];
    char actual_transaction_id[OCRA_KEY_ID_HEX_LENGTH + 1U];
    int matches;

    (void)memset(actual_operation, 0, sizeof(actual_operation));
    (void)memset(phase, 0, sizeof(phase));
    (void)memset(actual_transaction_id, 0,
                 sizeof(actual_transaction_id));
    matches = read_journal_header(server_root_fd, actual_operation, phase,
                                  actual_transaction_id) == 0 &&
              strcmp(actual_operation, operation) == 0 &&
              CRYPTO_memcmp(actual_transaction_id, transaction_id,
                            OCRA_KEY_ID_HEX_LENGTH) == 0;
    secure_memory_clear(actual_operation, sizeof(actual_operation));
    secure_memory_clear(phase, sizeof(phase));
    secure_memory_clear(actual_transaction_id,
                        sizeof(actual_transaction_id));
    return matches;
}

static int remove_admin_journal(int server_root_fd, const char *operation,
                                const char *transaction_id)
{
    if (!journal_identity_matches(server_root_fd, operation, transaction_id) ||
        unlinkat(server_root_fd, OCRA_ADMIN_JOURNAL_NAME, 0) != 0 ||
        enroll_fsync_directory(server_root_fd) != 0) {
        return -1;
    }
    return 0;
}

static int remove_staged(int directory_fd, const char *name, int *exists);

static int remove_transaction_artifact(int server_root_fd,
                                       const char *operation,
                                       const char *transaction_id,
                                       int directory_fd, const char *name,
                                       int *exists)
{
    if (!journal_identity_matches(server_root_fd, operation, transaction_id)) {
        return -1;
    }
    return remove_staged(directory_fd, name, exists);
}

static int parse_uintmax_strict(const char *value, uintmax_t *output)
{
    char *end = NULL;
    uintmax_t parsed;

    if (value == NULL || value[0] == '\0' || value[0] == '-') {
        return -1;
    }
    errno = 0;
    parsed = strtoumax(value, &end, 10);
    if (errno != 0 || end == NULL || *end != '\0') {
        return -1;
    }
    *output = parsed;
    return 0;
}

static int build_record(unsigned char record[OCRA_RECORD_CAPACITY],
                        size_t *record_length, char key_id[17U])
{
    unsigned char secret[OCRA_SECRET_BYTES];
    unsigned char key_bytes[OCRA_KEY_ID_RANDOM_BYTES];
    char encoded[53U];
    int count;
    int result = -1;

    (void)memset(secret, 0, sizeof(secret));
    (void)memset(key_bytes, 0, sizeof(key_bytes));
    (void)memset(encoded, 0, sizeof(encoded));
    if (enroll_random(secret, sizeof(secret)) != 0 ||
        enroll_random(key_bytes, sizeof(key_bytes)) != 0) {
        goto cleanup;
    }
    encode_base32(secret, encoded);
    encode_key_id(key_bytes, key_id);
    count = snprintf((char *)record, OCRA_RECORD_CAPACITY,
                     "version=1\n"
                     "suite=OCRA-1:HOTP-SHA256-8:QN10\n"
                     "key_id=%s\n"
                     "secret=%s\n"
                     "enabled=yes\n",
                     key_id, encoded);
    if (count < 0 || (size_t)count >= OCRA_RECORD_CAPACITY) {
        goto cleanup;
    }
    *record_length = (size_t)count;
    result = 0;

cleanup:
    secure_memory_clear(encoded, sizeof(encoded));
    secure_memory_clear(key_bytes, sizeof(key_bytes));
    secure_memory_clear(secret, sizeof(secret));
    return result;
}

static int serialize_record(const struct ocra_secret_record *source,
                            unsigned char record[OCRA_RECORD_CAPACITY],
                            size_t *record_length)
{
    char encoded[53U];
    int count;

    (void)memset(encoded, 0, sizeof(encoded));
    encode_base32(source->secret, encoded);
    count = snprintf((char *)record, OCRA_RECORD_CAPACITY,
                     "version=1\n"
                     "suite=OCRA-1:HOTP-SHA256-8:QN10\n"
                     "key_id=%s\n"
                     "secret=%s\n"
                     "enabled=yes\n",
                     source->key_id, encoded);
    secure_memory_clear(encoded, sizeof(encoded));
    if (count < 0 || (size_t)count >= OCRA_RECORD_CAPACITY) {
        return -1;
    }
    *record_length = (size_t)count;
    return 0;
}

static int read_record_at(int directory_fd, const char *name, uid_t uid,
                          gid_t gid, struct ocra_secret_record *record)
{
    unsigned char data[OCRA_SECRET_FILE_MAX + 1U];
    size_t length = 0U;
    int fd = -1;
    int result = -1;

    (void)memset(data, 0, sizeof(data));
    ocra_secret_record_clear(record);
    fd = openat(directory_fd, name,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || !metadata_is_file(fd, uid, gid) ||
        !path_matches_fd(directory_fd, name, fd)) {
        goto cleanup;
    }
    while (length < sizeof(data)) {
        ssize_t count = read(fd, data + length, sizeof(data) - length);

        if (count > 0) {
            length += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else if (count == 0) {
            break;
        } else {
            goto cleanup;
        }
    }
    if (length <= OCRA_SECRET_FILE_MAX &&
        ocra_secret_record_parse(data, length, record) == 0) {
        result = 0;
    }

cleanup:
    if (fd >= 0 && close(fd) != 0) {
        result = -1;
    }
    secure_memory_clear(data, sizeof(data));
    if (result != 0) {
        ocra_secret_record_clear(record);
    }
    return result;
}

static int records_match(const struct ocra_secret_record *left,
                         const struct ocra_secret_record *right)
{
    return CRYPTO_memcmp(left->secret, right->secret, OCRA_SECRET_BYTES) == 0 &&
           CRYPTO_memcmp(left->key_id, right->key_id,
                         OCRA_KEY_ID_HEX_LENGTH) == 0;
}

static int record_artifact_state(int directory_fd, const char *name,
                                 uid_t uid, gid_t gid,
                                 const char *expected_key, int *exists)
{
    struct ocra_secret_record record;
    struct stat status;
    int result = -1;

    ocra_secret_record_clear(&record);
    *exists = 0;
    if (fstatat(directory_fd, name, &status, AT_SYMLINK_NOFOLLOW) != 0) {
        result = errno == ENOENT ? 0 : -1;
        goto cleanup;
    }
    if (read_record_at(directory_fd, name, uid, gid, &record) != 0 ||
        strcmp(record.key_id, expected_key) != 0) {
        goto cleanup;
    }
    *exists = 1;
    result = 0;

cleanup:
    ocra_secret_record_clear(&record);
    return result;
}

static int format_name(char output[NAME_MAX + 1U], const char *base,
                       const char *suffix, const char *key_id);

static int read_confirmation(FILE *input,
                             char response[OCRA_RESPONSE_CAPACITY])
{
    size_t index;
    int character;

    (void)memset(response, 0, OCRA_RESPONSE_CAPACITY);
    for (index = 0U; index < OCRA_RESPONSE_DIGITS; ++index) {
        character = fgetc(input);
        if (character < '0' || character > '9') {
            return -1;
        }
        response[index] = (char)character;
    }
    character = fgetc(input);
    return character == '\n' ? 0 : -1;
}

static int remove_staged(int directory_fd, const char *name, int *exists)
{
    if (*exists != 0) {
        if (unlinkat(directory_fd, name, 0) != 0 && errno != ENOENT) {
            return -1;
        }
        if (enroll_fsync_directory(directory_fd) != 0) {
            return -1;
        }
        *exists = 0;
    }
    return 0;
}

static int restore_backup(int directory_fd, const char *backup,
                          const char *target, uid_t uid, gid_t gid,
                          const struct ocra_secret_record *expected,
                          const char *replacement_key,
                          const char *transaction_id,
                          int *backup_exists)
{
    struct ocra_secret_record record;
    struct ocra_secret_record current;
    unsigned char serialized[OCRA_RECORD_CAPACITY];
    char restore_name[NAME_MAX + 1U];
    size_t serialized_length = 0U;
    struct stat status;
    int restore_exists = 0;
    int result = -1;

    ocra_secret_record_clear(&record);
    ocra_secret_record_clear(&current);
    (void)memset(serialized, 0, sizeof(serialized));
    (void)memset(restore_name, 0, sizeof(restore_name));
    if (*backup_exists == 0) {
        goto cleanup;
    }
    if (read_record_at(directory_fd, backup, uid, gid, &record) != 0 ||
        !records_match(&record, expected)) {
        goto cleanup;
    }
    if (read_record_at(directory_fd, target, uid, gid, &current) == 0) {
        if (records_match(&current, expected)) {
            result = 0;
            goto cleanup;
        }
        if (replacement_key == NULL ||
            strcmp(current.key_id, replacement_key) != 0) {
            goto cleanup;
        }
    } else if (fstatat(directory_fd, target, &status, AT_SYMLINK_NOFOLLOW) ==
                   0 ||
               errno != ENOENT) {
        goto cleanup;
    }
    if (format_name(restore_name, target, "restore", transaction_id) != 0 ||
        serialize_record(expected, serialized, &serialized_length) != 0) {
        goto cleanup;
    }
    if (fstatat(directory_fd, restore_name, &status, AT_SYMLINK_NOFOLLOW) ==
        0) {
        restore_exists = 1;
        if (read_record_at(directory_fd, restore_name, uid, gid, &current) !=
                0 ||
            !records_match(&current, expected)) {
            goto cleanup;
        }
    } else if (errno != ENOENT ||
               stage_record(directory_fd, restore_name, uid, gid, serialized,
                            serialized_length) != 0) {
        goto cleanup;
    } else {
        restore_exists = 1;
    }
    if (restore_exists == 0 ||
        enroll_rename(directory_fd, restore_name, directory_fd, target) != 0 ||
        enroll_fsync_directory(directory_fd) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    secure_memory_clear(restore_name, sizeof(restore_name));
    secure_memory_clear(serialized, sizeof(serialized));
    ocra_secret_record_clear(&current);
    ocra_secret_record_clear(&record);
    return result;
}

static int enroll_remove_rate(int rate_root_fd, const char *uid_text,
                              const char *service, const char *key_id)
{
    return inject_fault(OCRA_ENROLL_FAULT_RATE_CLEANUP) != 0
               ? -1
               : ocra_rate_limit_remove_at(rate_root_fd, uid_text, service,
                                           key_id);
}

struct rotation_journal {
    char phase[16U];
    char transaction_id[OCRA_KEY_ID_HEX_LENGTH + 1U];
    char uid_text[OCRA_UID_TEXT_MAX_LENGTH + 1U];
    gid_t gid;
    char service[OCRA_SERVICE_MAX_LENGTH + 1U];
    char old_key[OCRA_KEY_ID_HEX_LENGTH + 1U];
    char new_key[OCRA_KEY_ID_HEX_LENGTH + 1U];
    dev_t client_device;
    ino_t client_inode;
    char client_name[NAME_MAX + 1U];
    char client_path[PATH_MAX];
};

static int write_rotation_journal(int server_fd, const char *journal_name,
                                  const struct rotation_journal *journal,
                                  const char *phase)
{
    unsigned char body[OCRA_JOURNAL_CAPACITY];
    char path_hex[PATH_MAX * 2U + 1U];
    char name_hex[NAME_MAX * 2U + 1U];
    char temp_name[NAME_MAX + 1U];
    int count;
    int staged = 0;
    int result = -1;

    (void)memset(body, 0, sizeof(body));
    (void)memset(path_hex, 0, sizeof(path_hex));
    (void)memset(name_hex, 0, sizeof(name_hex));
    if (journal == NULL ||
        ((strcmp(phase, "preparing") == 0 &&
          !target_is_absent(server_fd, journal_name)) ||
         (strcmp(phase, "preparing") != 0 &&
          !journal_identity_matches(server_fd, "rotate",
                                    journal->transaction_id))) ||
        hex_encode_text(journal->client_path, path_hex,
                                            sizeof(path_hex)) != 0 ||
        hex_encode_text(journal->client_name, name_hex, sizeof(name_hex)) !=
            0) {
        goto cleanup;
    }
    count = snprintf((char *)body, sizeof(body),
                     "version=2\noperation=rotate\nphase=%s\ntxid=%s\n"
                     "uid=%s\ngid=%" PRIuMAX "\nservice=%s\nold_key=%s\n"
                     "new_key=%s\nclient_dev=%" PRIuMAX
                     "\nclient_ino=%" PRIuMAX "\nclient_name=%s\n"
                     "client_path=%s\n",
                     phase, journal->transaction_id, journal->uid_text,
                     (uintmax_t)journal->gid, journal->service,
                     journal->old_key, journal->new_key,
                     (uintmax_t)journal->client_device,
                     (uintmax_t)journal->client_inode, name_hex, path_hex);
    if (count < 0 || (size_t)count >= sizeof(body) ||
        format_name(temp_name, journal_name, "journal",
                    journal->transaction_id) != 0 ||
        !target_is_absent(server_fd, temp_name) ||
        stage_record(server_fd, temp_name, server_owner_uid(),
                     server_owner_gid(), body, (size_t)count) != 0) {
        goto cleanup;
    }
    staged = 1;
    if (enroll_rename(server_fd, temp_name, server_fd, journal_name) != 0) {
        goto cleanup;
    }
    staged = 0;
    if (enroll_fsync_directory(server_fd) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (staged != 0) {
        (void)unlinkat(server_fd, temp_name, 0);
    }
    secure_memory_clear(body, sizeof(body));
    secure_memory_clear(path_hex, sizeof(path_hex));
    secure_memory_clear(name_hex, sizeof(name_hex));
    return result;
}

static int read_rotation_journal(int server_fd, const char *journal_name,
                                 struct rotation_journal *journal)
{
    unsigned char body[OCRA_JOURNAL_CAPACITY + 1U];
    int fd = -1;
    size_t length = 0U;
    char *cursor;
    const char *value;
    uintmax_t parsed_gid;
    uintmax_t parsed_device;
    uintmax_t parsed_inode;
    uid_t parsed_uid;
    int result = -1;

    (void)memset(body, 0, sizeof(body));
    (void)memset(journal, 0, sizeof(*journal));
    fd = openat(server_fd, journal_name,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || !metadata_is_file(fd, server_owner_uid(),
                                    server_owner_gid()) ||
        !path_matches_fd(server_fd, journal_name, fd)) {
        goto cleanup;
    }
    while (length < OCRA_JOURNAL_CAPACITY) {
        ssize_t count = read(fd, body + length,
                             OCRA_JOURNAL_CAPACITY - length);

        if (count > 0) {
            length += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else if (count == 0) {
            break;
        } else {
            goto cleanup;
        }
    }
    body[length] = '\0';
    cursor = (char *)body;
    value = journal_field(&cursor, "version=");
    if (value == NULL || strcmp(value, "2") != 0 ||
        (value = journal_field(&cursor, "operation=")) == NULL ||
        strcmp(value, "rotate") != 0 ||
        (value = journal_field(&cursor, "phase=")) == NULL ||
        strlen(value) >= sizeof(journal->phase)) {
        goto cleanup;
    }
    (void)strcpy(journal->phase, value);
    value = journal_field(&cursor, "txid=");
    if (!lowercase_hex_is_valid(value, OCRA_KEY_ID_HEX_LENGTH)) {
        goto cleanup;
    }
    (void)strcpy(journal->transaction_id, value);
    value = journal_field(&cursor, "uid=");
    if (value == NULL || strlen(value) >= sizeof(journal->uid_text) ||
        ocra_scope_parse_uid(value, &parsed_uid) != 0) {
        goto cleanup;
    }
    (void)strcpy(journal->uid_text, value);
    value = journal_field(&cursor, "gid=");
    if (parse_uintmax_strict(value, &parsed_gid) != 0 ||
        (uintmax_t)(gid_t)parsed_gid != parsed_gid) {
        goto cleanup;
    }
    journal->gid = (gid_t)parsed_gid;
    value = journal_field(&cursor, "service=");
    if (value == NULL || strlen(value) >= sizeof(journal->service) ||
        ocra_scope_validate_service(value) != 0) {
        goto cleanup;
    }
    (void)strcpy(journal->service, value);
    value = journal_field(&cursor, "old_key=");
    if (!lowercase_hex_is_valid(value, OCRA_KEY_ID_HEX_LENGTH)) {
        goto cleanup;
    }
    (void)strcpy(journal->old_key, value);
    value = journal_field(&cursor, "new_key=");
    if (!lowercase_hex_is_valid(value, OCRA_KEY_ID_HEX_LENGTH)) {
        goto cleanup;
    }
    (void)strcpy(journal->new_key, value);
    value = journal_field(&cursor, "client_dev=");
    if (parse_uintmax_strict(value, &parsed_device) != 0 ||
        (uintmax_t)(dev_t)parsed_device != parsed_device) {
        goto cleanup;
    }
    journal->client_device = (dev_t)parsed_device;
    value = journal_field(&cursor, "client_ino=");
    if (parse_uintmax_strict(value, &parsed_inode) != 0 ||
        (uintmax_t)(ino_t)parsed_inode != parsed_inode) {
        goto cleanup;
    }
    journal->client_inode = (ino_t)parsed_inode;
    value = journal_field(&cursor, "client_name=");
    if (hex_decode_text(value, journal->client_name,
                        sizeof(journal->client_name)) != 0 ||
        !component_is_safe(journal->client_name,
                           strlen(journal->client_name))) {
        goto cleanup;
    }
    value = journal_field(&cursor, "client_path=");
    if (hex_decode_text(value, journal->client_path,
                        sizeof(journal->client_path)) != 0 ||
        journal->client_path[0] != '/' || *cursor != '\0' ||
        (strcmp(journal->phase, "preparing") != 0 &&
         strcmp(journal->phase, "prepared") != 0 &&
         strcmp(journal->phase, "committing") != 0)) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (fd >= 0 && close(fd) != 0) {
        result = -1;
    }
    secure_memory_clear(body, sizeof(body));
    if (result != 0) {
        secure_memory_clear(journal, sizeof(*journal));
    }
    return result;
}

static int path_exists_regular(int directory_fd, const char *name)
{
    struct stat status;

    return fstatat(directory_fd, name, &status, AT_SYMLINK_NOFOLLOW) == 0 &&
           S_ISREG(status.st_mode);
}

static int recover_rotation(int server_root_fd, int rate_root_fd)
{
    struct rotation_journal journal;
    struct ocra_secret_record server_record;
    struct ocra_secret_record client_record;
    struct enroll_target client;
    char server_name[OCRA_SERVICE_MAX_LENGTH + sizeof(".conf")];
    char server_new[NAME_MAX + 1U];
    char server_backup[NAME_MAX + 1U];
    char client_new[NAME_MAX + 1U];
    char client_backup[NAME_MAX + 1U];
    uid_t uid = (uid_t)0;
    int server_fd = -1;
    int server_backup_exists;
    int client_backup_exists;
    int server_new_exists;
    int client_new_exists;
    int result = -1;

    (void)memset(&journal, 0, sizeof(journal));
    (void)memset(&client, 0, sizeof(client));
    client.directory_fd = -1;
    ocra_secret_record_clear(&server_record);
    ocra_secret_record_clear(&client_record);
    if (!path_exists_regular(server_root_fd, OCRA_ADMIN_JOURNAL_NAME)) {
        struct stat status;

        if (fstatat(server_root_fd, OCRA_ADMIN_JOURNAL_NAME, &status,
                    AT_SYMLINK_NOFOLLOW) != 0 &&
            errno == ENOENT) {
            result = 0;
        }
        goto cleanup;
    }
    if (read_rotation_journal(server_root_fd, OCRA_ADMIN_JOURNAL_NAME,
                              &journal) != 0 ||
        ocra_scope_parse_uid(journal.uid_text, &uid) != 0 ||
        snprintf(server_name, sizeof(server_name), "%s.conf",
                 journal.service) < 0 ||
        open_client_target(journal.client_path, uid, journal.gid, &client) != 0 ||
        client.device != journal.client_device ||
        client.inode != journal.client_inode ||
        strcmp(client.name, journal.client_name) != 0 ||
        (server_fd = open_existing_server_scope(server_root_fd,
                                                journal.uid_text)) < 0 ||
        format_name(server_new, server_name, "new",
                    journal.transaction_id) != 0 ||
        format_name(server_backup, server_name, "old",
                    journal.transaction_id) != 0 ||
        format_name(client_new, client.name, "new",
                    journal.transaction_id) != 0 ||
        format_name(client_backup, client.name, "old",
                    journal.transaction_id) != 0) {
        goto cleanup;
    }
    if (!journal_identity_matches(server_root_fd, "rotate",
                                  journal.transaction_id) ||
        record_artifact_state(server_fd, server_backup, server_owner_uid(),
                              server_owner_gid(), journal.old_key,
                              &server_backup_exists) != 0 ||
        record_artifact_state(client.directory_fd, client_backup, uid,
                              journal.gid, journal.old_key,
                              &client_backup_exists) != 0 ||
        record_artifact_state(server_fd, server_new, server_owner_uid(),
                              server_owner_gid(), journal.new_key,
                              &server_new_exists) != 0 ||
        record_artifact_state(client.directory_fd, client_new, uid,
                              journal.gid, journal.new_key,
                              &client_new_exists) != 0) {
        goto cleanup;
    }
    if (strcmp(journal.phase, "preparing") == 0) {
        /* PREPARING owns artifacts only and never mutates final targets. */
    } else if (strcmp(journal.phase, "prepared") == 0) {
        int targets_are_old =
            read_record_at(server_fd, server_name, server_owner_uid(),
                           server_owner_gid(), &server_record) == 0 &&
            read_record_at(client.directory_fd, client.name, uid, journal.gid,
                           &client_record) == 0 &&
            strcmp(server_record.key_id, journal.old_key) == 0 &&
            records_match(&server_record, &client_record);

        if (!targets_are_old) {
            if (!server_backup_exists || !client_backup_exists ||
                read_record_at(server_fd, server_backup, server_owner_uid(),
                               server_owner_gid(), &server_record) != 0 ||
                read_record_at(client.directory_fd, client_backup, uid,
                               journal.gid, &client_record) != 0 ||
                strcmp(server_record.key_id, journal.old_key) != 0 ||
                !records_match(&server_record, &client_record) ||
                !journal_identity_matches(server_root_fd, "rotate",
                                          journal.transaction_id) ||
                restore_backup(server_fd, server_backup, server_name,
                               server_owner_uid(), server_owner_gid(),
                               &server_record, journal.new_key,
                               journal.transaction_id,
                               &server_backup_exists) != 0 ||
                inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_RECOVERY) != 0 ||
                !journal_identity_matches(server_root_fd, "rotate",
                                          journal.transaction_id) ||
                restore_backup(client.directory_fd, client_backup, client.name,
                               uid, journal.gid, &client_record,
                               journal.new_key, journal.transaction_id,
                               &client_backup_exists) != 0) {
                goto cleanup;
            }
        }
    } else {
        if (read_record_at(server_fd, server_name, server_owner_uid(),
                           server_owner_gid(), &server_record) != 0 ||
            read_record_at(client.directory_fd, client.name, uid, journal.gid,
                           &client_record) != 0 ||
            strcmp(server_record.key_id, journal.new_key) != 0 ||
            strcmp(client_record.key_id, journal.new_key) != 0 ||
            !records_match(&server_record, &client_record) ||
            enroll_remove_rate(rate_root_fd, journal.uid_text, journal.service,
                               journal.old_key) != 0) {
            goto cleanup;
        }
    }
    if (server_new_exists != 0) {
        if (remove_transaction_artifact(server_root_fd, "rotate",
                                        journal.transaction_id, server_fd,
                                        server_new, &server_new_exists) != 0 ||
            inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_RECOVERY) != 0) {
            goto cleanup;
        }
    }
    if (client_new_exists != 0) {
        if (remove_transaction_artifact(server_root_fd, "rotate",
                                        journal.transaction_id,
                                        client.directory_fd, client_new,
                                        &client_new_exists) != 0 ||
            inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_RECOVERY) != 0) {
            goto cleanup;
        }
    }
    if (server_backup_exists != 0) {
        if (remove_transaction_artifact(server_root_fd, "rotate",
                                        journal.transaction_id, server_fd,
                                        server_backup,
                                        &server_backup_exists) != 0 ||
            inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_RECOVERY) != 0) {
            goto cleanup;
        }
    }
    if (client_backup_exists != 0) {
        if (remove_transaction_artifact(server_root_fd, "rotate",
                                        journal.transaction_id,
                                        client.directory_fd, client_backup,
                                        &client_backup_exists) != 0 ||
            inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_RECOVERY) != 0) {
            goto cleanup;
        }
    }
    if (remove_admin_journal(server_root_fd, "rotate",
                             journal.transaction_id) != 0 ||
        enroll_fsync_directory(server_fd) != 0 ||
        enroll_fsync_directory(client.directory_fd) != 0 ||
        enroll_fsync_directory(server_root_fd) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (server_fd >= 0) {
        (void)close(server_fd);
    }
    if (client.directory_fd >= 0) {
        (void)close(client.directory_fd);
    }
    ocra_secret_record_clear(&client_record);
    ocra_secret_record_clear(&server_record);
    secure_memory_clear(&journal, sizeof(journal));
    return result;
}

static int enroll_rotate(int server_root_fd, int rate_root_fd, uid_t uid,
                         gid_t gid, const char *uid_text, const char *service,
                         const char *client_path, FILE *input, FILE *output)
{
    struct ocra_secret_record old_server;
    struct ocra_secret_record old_client;
    struct ocra_secret_record fresh;
    struct rotation_journal journal;
    struct enroll_target client;
    unsigned char old_record[OCRA_RECORD_CAPACITY];
    unsigned char new_record[OCRA_RECORD_CAPACITY];
    char server_name[OCRA_SERVICE_MAX_LENGTH + sizeof(".conf")];
    char server_new[NAME_MAX + 1U];
    char server_backup[NAME_MAX + 1U];
    char client_new[NAME_MAX + 1U];
    char client_backup[NAME_MAX + 1U];
    char transaction_id[OCRA_KEY_ID_HEX_LENGTH + 1U];
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];
    char supplied[OCRA_RESPONSE_CAPACITY];
    char expected[OCRA_RESPONSE_CAPACITY];
    char fresh_key_id[OCRA_KEY_ID_HEX_LENGTH + 1U];
    size_t old_length = 0U;
    size_t new_length = 0U;
    unsigned int attempt;
    int server_fd = -1;
    int server_new_exists = 0;
    int client_new_exists = 0;
    int server_backup_exists = 0;
    int client_backup_exists = 0;
    int server_installed = 0;
    int client_installed = 0;
    int journal_exists = 0;
    int leave_transaction = 0;
    int transaction_committed = 0;
    int rollback_failed = 0;
    int result = -1;

    ocra_secret_record_clear(&old_server);
    ocra_secret_record_clear(&old_client);
    ocra_secret_record_clear(&fresh);
    (void)memset(&journal, 0, sizeof(journal));
    (void)memset(old_record, 0, sizeof(old_record));
    (void)memset(new_record, 0, sizeof(new_record));
    (void)memset(challenge, 0, sizeof(challenge));
    (void)memset(supplied, 0, sizeof(supplied));
    (void)memset(expected, 0, sizeof(expected));
    (void)memset(fresh_key_id, 0, sizeof(fresh_key_id));
    (void)memset(transaction_id, 0, sizeof(transaction_id));
    client.directory_fd = -1;
    if (snprintf(server_name, sizeof(server_name), "%s.conf", service) < 0 ||
        open_client_target(client_path, uid, gid, &client) != 0) {
        goto cleanup;
    }
    server_fd = open_server_scope(server_root_fd, uid_text);
    if (server_fd < 0 ||
        !target_is_absent(server_root_fd, OCRA_ADMIN_JOURNAL_NAME) ||
        read_record_at(server_fd, server_name, server_owner_uid(),
                       server_owner_gid(), &old_server) != 0 ||
        read_record_at(client.directory_fd, client.name, uid, gid,
                       &old_client) != 0 ||
        !records_match(&old_server, &old_client) ||
        serialize_record(&old_server, old_record, &old_length) != 0) {
        goto cleanup;
    }
    for (attempt = 0U; attempt < 8U; ++attempt) {
        if (build_record(new_record, &new_length, fresh_key_id) != 0 ||
            ocra_secret_record_parse(new_record, new_length, &fresh) != 0) {
            goto cleanup;
        }
        if (strcmp(fresh.key_id, old_server.key_id) != 0) {
            break;
        }
        ocra_secret_record_clear(&fresh);
        secure_memory_clear(new_record, sizeof(new_record));
    }
    if (attempt == 8U || build_transaction_id(transaction_id) != 0 ||
        format_name(server_new, server_name, "new", transaction_id) != 0 ||
        format_name(server_backup, server_name, "old", transaction_id) != 0 ||
        format_name(client_new, client.name, "new", transaction_id) != 0 ||
        format_name(client_backup, client.name, "old", transaction_id) != 0 ||
        snprintf(journal.uid_text, sizeof(journal.uid_text), "%s", uid_text) <
            0 ||
        snprintf(journal.service, sizeof(journal.service), "%s", service) < 0 ||
        snprintf(journal.client_name, sizeof(journal.client_name), "%s",
                 client.name) < 0 ||
        snprintf(journal.client_path, sizeof(journal.client_path), "%s",
                 client.path) < 0) {
        goto cleanup;
    }
    (void)strcpy(journal.transaction_id, transaction_id);
    (void)strcpy(journal.old_key, old_server.key_id);
    (void)strcpy(journal.new_key, fresh.key_id);
    journal.gid = gid;
    journal.client_device = client.device;
    journal.client_inode = client.inode;
    if (write_rotation_journal(server_root_fd, OCRA_ADMIN_JOURNAL_NAME,
                               &journal, "preparing") != 0) {
        goto cleanup;
    }
    journal_exists = 1;
    if (inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_PREPARE) != 0) {
        leave_transaction = 1;
        goto cleanup;
    }
    if (stage_record(server_fd, server_new, server_owner_uid(),
                     server_owner_gid(), new_record, new_length) != 0) {
        goto cleanup;
    }
    server_new_exists = 1;
    if (inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_PREPARE) != 0) {
        leave_transaction = 1;
        goto cleanup;
    }
    if (stage_record(client.directory_fd, client_new, uid, gid, new_record,
                     new_length) != 0) {
        goto cleanup;
    }
    client_new_exists = 1;
    if (inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_PREPARE) != 0) {
        leave_transaction = 1;
        goto cleanup;
    }
    if (stage_record(server_fd, server_backup, server_owner_uid(),
                     server_owner_gid(), old_record, old_length) != 0) {
        goto cleanup;
    }
    server_backup_exists = 1;
    if (inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_PREPARE) != 0) {
        leave_transaction = 1;
        goto cleanup;
    }
    if (stage_record(client.directory_fd, client_backup, uid, gid, old_record,
                     old_length) != 0) {
        goto cleanup;
    }
    client_backup_exists = 1;
    if (inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_PREPARE) != 0) {
        leave_transaction = 1;
        goto cleanup;
    }
    if (write_rotation_journal(server_root_fd, OCRA_ADMIN_JOURNAL_NAME,
                               &journal, "prepared") != 0) {
        goto cleanup;
    }
    if (inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_PREPARE) != 0) {
        leave_transaction = 1;
        goto cleanup;
    }
    if (enroll_rename(client.directory_fd, client_new, client.directory_fd,
                      client.name) != 0 ||
        enroll_fsync_directory(client.directory_fd) != 0) {
        goto cleanup;
    }
    client_new_exists = 0;
    client_installed = 1;
    if (inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_AFTER_CLIENT) != 0) {
        leave_transaction = 1;
        goto cleanup;
    }
    if (ocra_generate_challenge(challenge) != 0 ||
        fprintf(output, "Confirmation challenge: %s\n", challenge) < 0 ||
        fflush(output) != 0 || read_confirmation(input, supplied) != 0 ||
        ocra_compute_response(fresh.secret, sizeof(fresh.secret), challenge,
                              OCRA_CHALLENGE_DIGITS, expected,
                              sizeof(expected)) != 0 ||
        CRYPTO_memcmp(supplied, expected, OCRA_RESPONSE_DIGITS) != 0) {
        goto cleanup;
    }
    if (enroll_rename(server_fd, server_new, server_fd, server_name) != 0 ||
        enroll_fsync_directory(server_fd) != 0) {
        goto cleanup;
    }
    server_new_exists = 0;
    server_installed = 1;
    if (write_rotation_journal(server_root_fd, OCRA_ADMIN_JOURNAL_NAME,
                               &journal, "committing") != 0) {
        goto cleanup;
    }
    if (inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_AFTER_COMMITTING) != 0) {
        leave_transaction = 1;
        goto cleanup;
    }
    if (enroll_remove_rate(rate_root_fd, uid_text, service,
                           old_server.key_id) != 0) {
        goto cleanup;
    }
    transaction_committed = 1;
    if (remove_transaction_artifact(server_root_fd, "rotate", transaction_id,
                                    server_fd, server_backup,
                                    &server_backup_exists) != 0 ||
        enroll_fsync_directory(server_fd) != 0 ||
        remove_transaction_artifact(server_root_fd, "rotate", transaction_id,
                                    client.directory_fd, client_backup,
                                    &client_backup_exists) != 0 ||
        enroll_fsync_directory(client.directory_fd) != 0 ||
        remove_admin_journal(server_root_fd, "rotate", transaction_id) != 0 ||
        enroll_fsync_directory(server_fd) != 0 ||
        enroll_fsync_directory(server_root_fd) != 0 ||
        fprintf(output,
                "ocra-enroll: rotate uid=%s service=%s completed\n",
                uid_text, service) < 0 ||
        fflush(output) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (leave_transaction != 0) {
        goto close_and_clear;
    }
    if (result != 0 &&
        journal_identity_matches(server_root_fd, "rotate", transaction_id)) {
        (void)recover_rotation(server_root_fd, rate_root_fd);
        goto close_and_clear;
    }
    if (result != 0 && transaction_committed == 0) {
        if (server_installed != 0) {
            if (restore_backup(server_fd, server_backup, server_name,
                               server_owner_uid(), server_owner_gid(),
                               &old_server, fresh.key_id, transaction_id,
                               &server_backup_exists) != 0) {
                rollback_failed = 1;
            }
        }
        if (client_installed != 0) {
            if (restore_backup(client.directory_fd, client_backup,
                               client.name, uid, gid, &old_client,
                               fresh.key_id, transaction_id,
                               &client_backup_exists) != 0) {
                rollback_failed = 1;
            }
        }
    }
    if (rollback_failed != 0) {
        goto close_and_clear;
    }
    (void)remove_staged(server_fd, server_new, &server_new_exists);
    (void)remove_staged(client.directory_fd, client_new, &client_new_exists);
    (void)remove_staged(server_fd, server_backup, &server_backup_exists);
    (void)remove_staged(client.directory_fd, client_backup,
                        &client_backup_exists);
    if (journal_exists != 0 && transaction_committed == 0) {
        (void)remove_admin_journal(server_root_fd, "rotate", transaction_id);
    }
close_and_clear:
    if (server_fd >= 0) {
        (void)fsync(server_fd);
        (void)close(server_fd);
    }
    (void)fsync(server_root_fd);
    secure_memory_clear(transaction_id, sizeof(transaction_id));
    secure_memory_clear(&journal, sizeof(journal));
    if (client.directory_fd >= 0) {
        (void)fsync(client.directory_fd);
        (void)close(client.directory_fd);
    }
    secure_memory_clear(fresh_key_id, sizeof(fresh_key_id));
    secure_memory_clear(expected, sizeof(expected));
    secure_memory_clear(supplied, sizeof(supplied));
    secure_memory_clear(challenge, sizeof(challenge));
    secure_memory_clear(new_record, sizeof(new_record));
    secure_memory_clear(old_record, sizeof(old_record));
    ocra_secret_record_clear(&fresh);
    ocra_secret_record_clear(&old_client);
    ocra_secret_record_clear(&old_server);
    return result;
}

static int format_name(char output[NAME_MAX + 1U], const char *base,
                       const char *suffix, const char *key_id)
{
    int count = snprintf(output, NAME_MAX + 1U, "%s.ocra-%s.%s", base,
                         key_id, suffix);

    return count > 0 && count <= NAME_MAX ? 0 : -1;
}

struct add_journal {
    char phase[16U];
    char transaction_id[OCRA_KEY_ID_HEX_LENGTH + 1U];
    char uid_text[OCRA_UID_TEXT_MAX_LENGTH + 1U];
    gid_t gid;
    char service[OCRA_SERVICE_MAX_LENGTH + 1U];
    char new_key[OCRA_KEY_ID_HEX_LENGTH + 1U];
    dev_t client_device;
    ino_t client_inode;
    char client_name[NAME_MAX + 1U];
    char client_path[PATH_MAX];
};

static int write_add_journal(int server_fd, const char *journal_name,
                             const struct add_journal *journal,
                             const char *phase)
{
    unsigned char body[OCRA_JOURNAL_CAPACITY];
    char path_hex[PATH_MAX * 2U + 1U];
    char name_hex[NAME_MAX * 2U + 1U];
    char temp_name[NAME_MAX + 1U];
    int count;
    int staged = 0;
    int result = -1;

    (void)memset(body, 0, sizeof(body));
    (void)memset(path_hex, 0, sizeof(path_hex));
    (void)memset(name_hex, 0, sizeof(name_hex));
    if (journal == NULL ||
        ((strcmp(phase, "preparing") == 0 &&
          !target_is_absent(server_fd, journal_name)) ||
         (strcmp(phase, "preparing") != 0 &&
          !journal_identity_matches(server_fd, "add",
                                    journal->transaction_id))) ||
        hex_encode_text(journal->client_path, path_hex,
                                            sizeof(path_hex)) != 0 ||
        hex_encode_text(journal->client_name, name_hex, sizeof(name_hex)) !=
            0) {
        goto cleanup;
    }
    count = snprintf((char *)body, sizeof(body),
                     "version=2\noperation=add\nphase=%s\ntxid=%s\n"
                     "uid=%s\ngid=%" PRIuMAX "\nservice=%s\nnew_key=%s\n"
                     "client_dev=%" PRIuMAX "\nclient_ino=%" PRIuMAX
                     "\nclient_name=%s\nclient_path=%s\n",
                     phase, journal->transaction_id, journal->uid_text,
                     (uintmax_t)journal->gid, journal->service,
                     journal->new_key, (uintmax_t)journal->client_device,
                     (uintmax_t)journal->client_inode, name_hex, path_hex);
    if (count < 0 || (size_t)count >= sizeof(body) ||
        format_name(temp_name, journal_name, "journal",
                    journal->transaction_id) != 0 ||
        !target_is_absent(server_fd, temp_name) ||
        stage_record(server_fd, temp_name, server_owner_uid(),
                     server_owner_gid(), body, (size_t)count) != 0) {
        goto cleanup;
    }
    staged = 1;
    if (enroll_rename(server_fd, temp_name, server_fd, journal_name) != 0) {
        goto cleanup;
    }
    staged = 0;
    if (enroll_fsync_directory(server_fd) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (staged != 0) {
        (void)unlinkat(server_fd, temp_name, 0);
    }
    secure_memory_clear(body, sizeof(body));
    secure_memory_clear(path_hex, sizeof(path_hex));
    secure_memory_clear(name_hex, sizeof(name_hex));
    return result;
}

static int read_add_journal(int server_fd, const char *journal_name,
                            struct add_journal *journal)
{
    unsigned char body[OCRA_JOURNAL_CAPACITY + 1U];
    size_t length = 0U;
    char *cursor;
    const char *value;
    uintmax_t parsed_gid;
    uintmax_t parsed_device;
    uintmax_t parsed_inode;
    uid_t parsed_uid;
    int fd = -1;
    int result = -1;

    (void)memset(body, 0, sizeof(body));
    (void)memset(journal, 0, sizeof(*journal));
    fd = openat(server_fd, journal_name,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || !metadata_is_file(fd, server_owner_uid(),
                                    server_owner_gid()) ||
        !path_matches_fd(server_fd, journal_name, fd)) {
        goto cleanup;
    }
    while (length < OCRA_JOURNAL_CAPACITY) {
        ssize_t count = read(fd, body + length,
                             OCRA_JOURNAL_CAPACITY - length);

        if (count > 0) {
            length += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else if (count == 0) {
            break;
        } else {
            goto cleanup;
        }
    }
    body[length] = '\0';
    cursor = (char *)body;
    value = journal_field(&cursor, "version=");
    if (value == NULL || strcmp(value, "2") != 0 ||
        (value = journal_field(&cursor, "operation=")) == NULL ||
        strcmp(value, "add") != 0 ||
        (value = journal_field(&cursor, "phase=")) == NULL ||
        strlen(value) >= sizeof(journal->phase)) {
        goto cleanup;
    }
    (void)strcpy(journal->phase, value);
    value = journal_field(&cursor, "txid=");
    if (!lowercase_hex_is_valid(value, OCRA_KEY_ID_HEX_LENGTH)) {
        goto cleanup;
    }
    (void)strcpy(journal->transaction_id, value);
    value = journal_field(&cursor, "uid=");
    if (value == NULL || strlen(value) >= sizeof(journal->uid_text) ||
        ocra_scope_parse_uid(value, &parsed_uid) != 0) {
        goto cleanup;
    }
    (void)strcpy(journal->uid_text, value);
    value = journal_field(&cursor, "gid=");
    if (parse_uintmax_strict(value, &parsed_gid) != 0 ||
        (uintmax_t)(gid_t)parsed_gid != parsed_gid) {
        goto cleanup;
    }
    journal->gid = (gid_t)parsed_gid;
    value = journal_field(&cursor, "service=");
    if (value == NULL || strlen(value) >= sizeof(journal->service) ||
        ocra_scope_validate_service(value) != 0) {
        goto cleanup;
    }
    (void)strcpy(journal->service, value);
    value = journal_field(&cursor, "new_key=");
    if (!lowercase_hex_is_valid(value, OCRA_KEY_ID_HEX_LENGTH)) {
        goto cleanup;
    }
    (void)strcpy(journal->new_key, value);
    value = journal_field(&cursor, "client_dev=");
    if (parse_uintmax_strict(value, &parsed_device) != 0 ||
        (uintmax_t)(dev_t)parsed_device != parsed_device) {
        goto cleanup;
    }
    journal->client_device = (dev_t)parsed_device;
    value = journal_field(&cursor, "client_ino=");
    if (parse_uintmax_strict(value, &parsed_inode) != 0 ||
        (uintmax_t)(ino_t)parsed_inode != parsed_inode) {
        goto cleanup;
    }
    journal->client_inode = (ino_t)parsed_inode;
    value = journal_field(&cursor, "client_name=");
    if (hex_decode_text(value, journal->client_name,
                        sizeof(journal->client_name)) != 0 ||
        !component_is_safe(journal->client_name,
                           strlen(journal->client_name))) {
        goto cleanup;
    }
    value = journal_field(&cursor, "client_path=");
    if (hex_decode_text(value, journal->client_path,
                        sizeof(journal->client_path)) != 0 ||
        journal->client_path[0] != '/' || *cursor != '\0' ||
        (strcmp(journal->phase, "preparing") != 0 &&
         strcmp(journal->phase, "prepared") != 0 &&
         strcmp(journal->phase, "committing") != 0)) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (fd >= 0 && close(fd) != 0) {
        result = -1;
    }
    secure_memory_clear(body, sizeof(body));
    if (result != 0) {
        secure_memory_clear(journal, sizeof(*journal));
    }
    return result;
}

static int remove_target_for_key(int directory_fd, const char *name, uid_t uid,
                                 gid_t gid, const char *key_id)
{
    struct ocra_secret_record record;
    struct stat status;
    int result = -1;

    ocra_secret_record_clear(&record);
    if (fstatat(directory_fd, name, &status, AT_SYMLINK_NOFOLLOW) != 0) {
        result = errno == ENOENT ? 0 : -1;
        goto cleanup;
    }
    if (read_record_at(directory_fd, name, uid, gid, &record) != 0 ||
        strcmp(record.key_id, key_id) != 0 ||
        unlinkat(directory_fd, name, 0) != 0 ||
        enroll_fsync_directory(directory_fd) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    ocra_secret_record_clear(&record);
    return result;
}

static int recover_add(int server_root_fd)
{
    struct add_journal journal;
    struct ocra_secret_record server_record;
    struct ocra_secret_record client_record;
    struct enroll_target client;
    struct stat status;
    char server_name[OCRA_SERVICE_MAX_LENGTH + sizeof(".conf")];
    char server_new[NAME_MAX + 1U];
    char client_new[NAME_MAX + 1U];
    uid_t uid = (uid_t)0;
    int server_fd = -1;
    int server_new_exists;
    int client_new_exists;
    int result = -1;

    (void)memset(&journal, 0, sizeof(journal));
    (void)memset(&client, 0, sizeof(client));
    client.directory_fd = -1;
    ocra_secret_record_clear(&server_record);
    ocra_secret_record_clear(&client_record);
    if (fstatat(server_root_fd, OCRA_ADMIN_JOURNAL_NAME, &status,
                AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            result = 0;
        }
        goto cleanup;
    }
    if (!S_ISREG(status.st_mode) ||
        read_add_journal(server_root_fd, OCRA_ADMIN_JOURNAL_NAME, &journal) !=
            0 ||
        ocra_scope_parse_uid(journal.uid_text, &uid) != 0 ||
        snprintf(server_name, sizeof(server_name), "%s.conf",
                 journal.service) < 0 ||
        open_client_target(journal.client_path, uid, journal.gid, &client) != 0 ||
        client.device != journal.client_device ||
        client.inode != journal.client_inode ||
        strcmp(client.name, journal.client_name) != 0 ||
        (server_fd = open_existing_server_scope(server_root_fd,
                                                journal.uid_text)) < 0 ||
        format_name(server_new, server_name, "new",
                    journal.transaction_id) != 0 ||
        format_name(client_new, client.name, "new",
                    journal.transaction_id) != 0) {
        goto cleanup;
    }
    if (!journal_identity_matches(server_root_fd, "add",
                                  journal.transaction_id) ||
        record_artifact_state(server_fd, server_new, server_owner_uid(),
                              server_owner_gid(), journal.new_key,
                              &server_new_exists) != 0 ||
        record_artifact_state(client.directory_fd, client_new, uid,
                              journal.gid, journal.new_key,
                              &client_new_exists) != 0) {
        goto cleanup;
    }
    if (strcmp(journal.phase, "preparing") == 0) {
        /* PREPARING owns artifacts only and never mutates final targets. */
    } else if (strcmp(journal.phase, "prepared") == 0) {
        if (!journal_identity_matches(server_root_fd, "add",
                                      journal.transaction_id) ||
            remove_target_for_key(server_fd, server_name, server_owner_uid(),
                                  server_owner_gid(), journal.new_key) != 0 ||
            !journal_identity_matches(server_root_fd, "add",
                                      journal.transaction_id) ||
            remove_target_for_key(client.directory_fd, client.name, uid,
                                  journal.gid,
                                  journal.new_key) != 0) {
            goto cleanup;
        }
    } else if (read_record_at(server_fd, server_name, server_owner_uid(),
                              server_owner_gid(), &server_record) != 0 ||
               read_record_at(client.directory_fd, client.name, uid,
                              journal.gid,
                              &client_record) != 0 ||
               strcmp(server_record.key_id, journal.new_key) != 0 ||
               !records_match(&server_record, &client_record)) {
        goto cleanup;
    }
    if (server_new_exists != 0 &&
        (remove_transaction_artifact(server_root_fd, "add",
                                     journal.transaction_id, server_fd,
                                     server_new, &server_new_exists) != 0 ||
         inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_RECOVERY) != 0)) {
        goto cleanup;
    }
    if (client_new_exists != 0 &&
        (remove_transaction_artifact(server_root_fd, "add",
                                     journal.transaction_id,
                                     client.directory_fd, client_new,
                                     &client_new_exists) != 0 ||
         inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_RECOVERY) != 0)) {
        goto cleanup;
    }
    if (remove_admin_journal(server_root_fd, "add",
                             journal.transaction_id) != 0 ||
        enroll_fsync_directory(server_fd) != 0 ||
        enroll_fsync_directory(client.directory_fd) != 0 ||
        enroll_fsync_directory(server_root_fd) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (server_fd >= 0) {
        (void)close(server_fd);
    }
    if (client.directory_fd >= 0) {
        (void)close(client.directory_fd);
    }
    ocra_secret_record_clear(&client_record);
    ocra_secret_record_clear(&server_record);
    secure_memory_clear(&journal, sizeof(journal));
    return result;
}

struct revoke_journal {
    char phase[16U];
    char transaction_id[OCRA_KEY_ID_HEX_LENGTH + 1U];
    char uid_text[OCRA_UID_TEXT_MAX_LENGTH + 1U];
    gid_t gid;
    char service[OCRA_SERVICE_MAX_LENGTH + 1U];
    char old_key[OCRA_KEY_ID_HEX_LENGTH + 1U];
};

static int write_revoke_journal(int server_root_fd,
                                const struct revoke_journal *journal,
                                const char *phase)
{
    unsigned char body[512U];
    char temp_name[NAME_MAX + 1U];
    int count;
    int staged = 0;
    int result = -1;

    (void)memset(body, 0, sizeof(body));
    if (journal == NULL ||
        ((strcmp(phase, "preparing") == 0 &&
          !target_is_absent(server_root_fd, OCRA_ADMIN_JOURNAL_NAME)) ||
         (strcmp(phase, "preparing") != 0 &&
          !journal_identity_matches(server_root_fd, "revoke",
                                    journal->transaction_id)))) {
        goto cleanup;
    }
    count = snprintf((char *)body, sizeof(body),
                     "version=2\noperation=revoke\nphase=%s\ntxid=%s\n"
                     "uid=%s\ngid=%" PRIuMAX "\nservice=%s\nold_key=%s\n",
                     phase, journal->transaction_id, journal->uid_text,
                     (uintmax_t)journal->gid, journal->service,
                     journal->old_key);
    if (count < 0 || (size_t)count >= sizeof(body) ||
        format_name(temp_name, OCRA_ADMIN_JOURNAL_NAME, "journal",
                    journal->transaction_id) != 0 ||
        !target_is_absent(server_root_fd, temp_name) ||
        stage_record(server_root_fd, temp_name, server_owner_uid(),
                     server_owner_gid(), body, (size_t)count) != 0) {
        goto cleanup;
    }
    staged = 1;
    if (enroll_rename(server_root_fd, temp_name, server_root_fd,
                      OCRA_ADMIN_JOURNAL_NAME) != 0) {
        goto cleanup;
    }
    staged = 0;
    if (enroll_fsync_directory(server_root_fd) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (staged != 0) {
        (void)unlinkat(server_root_fd, temp_name, 0);
    }
    secure_memory_clear(body, sizeof(body));
    return result;
}

static int read_revoke_journal(int server_root_fd,
                               struct revoke_journal *journal)
{
    unsigned char body[513U];
    size_t length = 0U;
    char *cursor;
    const char *value;
    uintmax_t parsed_gid;
    uid_t parsed_uid;
    int fd = -1;
    int result = -1;

    (void)memset(body, 0, sizeof(body));
    (void)memset(journal, 0, sizeof(*journal));
    fd = openat(server_root_fd, OCRA_ADMIN_JOURNAL_NAME,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || !metadata_is_file(fd, server_owner_uid(),
                                    server_owner_gid()) ||
        !path_matches_fd(server_root_fd, OCRA_ADMIN_JOURNAL_NAME, fd)) {
        goto cleanup;
    }
    while (length < sizeof(body) - 1U) {
        ssize_t count = read(fd, body + length, sizeof(body) - 1U - length);

        if (count > 0) {
            length += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else if (count == 0) {
            break;
        } else {
            goto cleanup;
        }
    }
    body[length] = '\0';
    cursor = (char *)body;
    value = journal_field(&cursor, "version=");
    if (value == NULL || strcmp(value, "2") != 0 ||
        (value = journal_field(&cursor, "operation=")) == NULL ||
        strcmp(value, "revoke") != 0 ||
        (value = journal_field(&cursor, "phase=")) == NULL ||
        strlen(value) >= sizeof(journal->phase)) {
        goto cleanup;
    }
    (void)strcpy(journal->phase, value);
    value = journal_field(&cursor, "txid=");
    if (!lowercase_hex_is_valid(value, OCRA_KEY_ID_HEX_LENGTH)) {
        goto cleanup;
    }
    (void)strcpy(journal->transaction_id, value);
    value = journal_field(&cursor, "uid=");
    if (value == NULL || strlen(value) >= sizeof(journal->uid_text) ||
        ocra_scope_parse_uid(value, &parsed_uid) != 0) {
        goto cleanup;
    }
    (void)strcpy(journal->uid_text, value);
    value = journal_field(&cursor, "gid=");
    if (parse_uintmax_strict(value, &parsed_gid) != 0 ||
        (uintmax_t)(gid_t)parsed_gid != parsed_gid) {
        goto cleanup;
    }
    journal->gid = (gid_t)parsed_gid;
    value = journal_field(&cursor, "service=");
    if (value == NULL || strlen(value) >= sizeof(journal->service) ||
        ocra_scope_validate_service(value) != 0) {
        goto cleanup;
    }
    (void)strcpy(journal->service, value);
    value = journal_field(&cursor, "old_key=");
    if (!lowercase_hex_is_valid(value, OCRA_KEY_ID_HEX_LENGTH) ||
        *cursor != '\0' ||
        (strcmp(journal->phase, "preparing") != 0 &&
         strcmp(journal->phase, "prepared") != 0 &&
         strcmp(journal->phase, "committing") != 0)) {
        goto cleanup;
    }
    (void)strcpy(journal->old_key, value);
    result = 0;

cleanup:
    if (fd >= 0 && close(fd) != 0) {
        result = -1;
    }
    secure_memory_clear(body, sizeof(body));
    if (result != 0) {
        secure_memory_clear(journal, sizeof(*journal));
    }
    return result;
}

static int recover_revoke(int server_root_fd, int rate_root_fd)
{
    struct revoke_journal journal;
    struct ocra_secret_record backup_record;
    struct ocra_secret_record target_record;
    char server_name[OCRA_SERVICE_MAX_LENGTH + sizeof(".conf")];
    char backup_name[NAME_MAX + 1U];
    int server_fd = -1;
    int backup_exists;
    int result = -1;

    (void)memset(&journal, 0, sizeof(journal));
    ocra_secret_record_clear(&backup_record);
    ocra_secret_record_clear(&target_record);
    if (read_revoke_journal(server_root_fd, &journal) != 0 ||
        snprintf(server_name, sizeof(server_name), "%s.conf",
                 journal.service) < 0 ||
        (server_fd = open_existing_server_scope(server_root_fd,
                                                journal.uid_text)) < 0 ||
        format_name(backup_name, server_name, "revoked",
                    journal.transaction_id) != 0) {
        goto cleanup;
    }
    if (!journal_identity_matches(server_root_fd, "revoke",
                                  journal.transaction_id) ||
        record_artifact_state(server_fd, backup_name, server_owner_uid(),
                              server_owner_gid(), journal.old_key,
                              &backup_exists) != 0) {
        goto cleanup;
    }
    if (strcmp(journal.phase, "preparing") == 0) {
        /* PREPARING owns artifacts only and never mutates final targets. */
    } else if (strcmp(journal.phase, "prepared") == 0) {
        if (read_record_at(server_fd, server_name, server_owner_uid(),
                           server_owner_gid(), &target_record) != 0 ||
            strcmp(target_record.key_id, journal.old_key) != 0 ||
            (backup_exists != 0 &&
             (read_record_at(server_fd, backup_name, server_owner_uid(),
                             server_owner_gid(), &backup_record) != 0 ||
              !records_match(&backup_record, &target_record)))) {
            goto cleanup;
        }
    } else if (!journal_identity_matches(server_root_fd, "revoke",
                                         journal.transaction_id) ||
               remove_target_for_key(server_fd, server_name,
                                     server_owner_uid(), server_owner_gid(),
                                     journal.old_key) != 0 ||
               !journal_identity_matches(server_root_fd, "revoke",
                                         journal.transaction_id) ||
               enroll_remove_rate(rate_root_fd, journal.uid_text,
                                  journal.service, journal.old_key) != 0) {
        goto cleanup;
    }
    if (backup_exists != 0 &&
        (remove_transaction_artifact(server_root_fd, "revoke",
                                     journal.transaction_id, server_fd,
                                     backup_name, &backup_exists) != 0 ||
         inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_RECOVERY) != 0)) {
        goto cleanup;
    }
    if (enroll_fsync_directory(server_fd) != 0 ||
        remove_admin_journal(server_root_fd, "revoke",
                             journal.transaction_id) != 0 ||
        enroll_fsync_directory(server_root_fd) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (server_fd >= 0) {
        (void)close(server_fd);
    }
    ocra_secret_record_clear(&target_record);
    ocra_secret_record_clear(&backup_record);
    secure_memory_clear(&journal, sizeof(journal));
    return result;
}

static int read_pending_operation(int server_root_fd, char operation[8U])
{
    char prefix[64U];
    int fd = -1;
    ssize_t count;
    int result = -1;

    (void)memset(prefix, 0, sizeof(prefix));
    operation[0] = '\0';
    fd = openat(server_root_fd, OCRA_ADMIN_JOURNAL_NAME,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        return errno == ENOENT ? 1 : -1;
    }
    if (!metadata_is_file(fd, server_owner_uid(), server_owner_gid()) ||
        !path_matches_fd(server_root_fd, OCRA_ADMIN_JOURNAL_NAME, fd)) {
        goto cleanup;
    }
    do {
        count = pread(fd, prefix, sizeof(prefix) - 1U, (off_t)0);
    } while (count < 0 && errno == EINTR);
    if (count <= 0) {
        goto cleanup;
    }
    prefix[count] = '\0';
    if (sscanf(prefix, "version=2\noperation=%7[a-z]\n", operation) == 1 &&
        (strcmp(operation, "add") == 0 ||
         strcmp(operation, "rotate") == 0 ||
         strcmp(operation, "revoke") == 0)) {
        result = 0;
    }

cleanup:
    if (close(fd) != 0) {
        result = -1;
    }
    secure_memory_clear(prefix, sizeof(prefix));
    return result;
}

static int recover_pending_transaction(int server_root_fd, int rate_root_fd)
{
    char operation[8U];
    int status;
    int result = -1;

    (void)memset(operation, 0, sizeof(operation));
    status = read_pending_operation(server_root_fd, operation);
    if (status == 1) {
        result = 0;
    } else if (status == 0 && strcmp(operation, "add") == 0) {
        result = recover_add(server_root_fd);
    } else if (status == 0 && strcmp(operation, "rotate") == 0) {
        result = recover_rotation(server_root_fd, rate_root_fd);
    } else if (status == 0 && strcmp(operation, "revoke") == 0) {
        result = recover_revoke(server_root_fd, rate_root_fd);
    }
    secure_memory_clear(operation, sizeof(operation));
    return result;
}

static int rollback_created_target(int directory_fd, const char *name)
{
    if (unlinkat(directory_fd, name, 0) != 0 && errno != ENOENT) {
        return -1;
    }
    return enroll_fsync_directory(directory_fd);
}

static int enroll_add(int server_root_fd, uid_t uid, gid_t gid,
                      const char *uid_text, const char *service,
                      const char *client_path, FILE *output)
{
    unsigned char record[OCRA_RECORD_CAPACITY];
    char key_id[OCRA_KEY_ID_HEX_LENGTH + 1U];
    char transaction_id[OCRA_KEY_ID_HEX_LENGTH + 1U];
    char server_name[OCRA_SERVICE_MAX_LENGTH + sizeof(".conf")];
    char server_temp[NAME_MAX + 1U];
    char client_temp[NAME_MAX + 1U];
    struct enroll_target client;
    struct add_journal journal;
    size_t record_length = 0U;
    int server_fd = -1;
    int server_staged = 0;
    int client_staged = 0;
    int server_installed = 0;
    int client_installed = 0;
    int journal_exists = 0;
    int leave_transaction = 0;
    int transaction_committed = 0;
    int rollback_failed = 0;
    int result = -1;

    (void)memset(record, 0, sizeof(record));
    (void)memset(key_id, 0, sizeof(key_id));
    (void)memset(transaction_id, 0, sizeof(transaction_id));
    (void)memset(&journal, 0, sizeof(journal));
    client.directory_fd = -1;
    if (snprintf(server_name, sizeof(server_name), "%s.conf", service) < 0 ||
        open_client_target(client_path, uid, gid, &client) != 0) {
        goto cleanup;
    }
    server_fd = open_server_scope(server_root_fd, uid_text);
    if (server_fd < 0 ||
        !target_is_absent(server_root_fd, OCRA_ADMIN_JOURNAL_NAME) ||
        !target_is_absent(server_fd, server_name) ||
        !target_is_absent(client.directory_fd, client.name) ||
        build_record(record, &record_length, key_id) != 0 ||
        build_transaction_id(transaction_id) != 0 ||
        format_name(server_temp, server_name, "new", transaction_id) != 0 ||
        format_name(client_temp, client.name, "new", transaction_id) != 0 ||
        snprintf(journal.uid_text, sizeof(journal.uid_text), "%s", uid_text) <
            0 ||
        snprintf(journal.service, sizeof(journal.service), "%s", service) < 0 ||
        snprintf(journal.client_name, sizeof(journal.client_name), "%s",
                 client.name) < 0 ||
        snprintf(journal.client_path, sizeof(journal.client_path), "%s",
                 client.path) < 0) {
        goto cleanup;
    }
    (void)strcpy(journal.transaction_id, transaction_id);
    (void)strcpy(journal.new_key, key_id);
    journal.gid = gid;
    journal.client_device = client.device;
    journal.client_inode = client.inode;
    if (write_add_journal(server_root_fd, OCRA_ADMIN_JOURNAL_NAME, &journal,
                          "preparing") != 0) {
        goto cleanup;
    }
    journal_exists = 1;
    if (stage_record(server_fd, server_temp, server_owner_uid(),
                     server_owner_gid(), record, record_length) != 0) {
        goto cleanup;
    }
    server_staged = 1;
    if (stage_record(client.directory_fd, client_temp, uid, gid, record,
                     record_length) != 0) {
        goto cleanup;
    }
    client_staged = 1;
    if (write_add_journal(server_root_fd, OCRA_ADMIN_JOURNAL_NAME, &journal,
                          "prepared") != 0) {
        goto cleanup;
    }
    if (enroll_rename(server_fd, server_temp, server_fd, server_name) != 0) {
        goto cleanup;
    }
    server_staged = 0;
    server_installed = 1;
    if (enroll_fsync_directory(server_fd) != 0) {
        goto cleanup;
    }
    if (inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_AFTER_ADD_SERVER) != 0) {
        leave_transaction = 1;
        goto cleanup;
    }
    if (
        enroll_rename(client.directory_fd, client_temp, client.directory_fd,
                      client.name) != 0) {
        goto cleanup;
    }
    client_staged = 0;
    client_installed = 1;
    if (enroll_fsync_directory(client.directory_fd) != 0 ||
        write_add_journal(server_root_fd, OCRA_ADMIN_JOURNAL_NAME, &journal,
                          "committing") != 0) {
        goto cleanup;
    }
    transaction_committed = 1;
    if (remove_admin_journal(server_root_fd, "add", transaction_id) != 0 ||
        fprintf(output, "ocra-enroll: add uid=%s service=%s completed\n",
                uid_text, service) < 0 ||
        fflush(output) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (leave_transaction != 0) {
        goto close_and_clear;
    }
    if (result != 0 &&
        journal_identity_matches(server_root_fd, "add", transaction_id)) {
        (void)recover_add(server_root_fd);
        goto close_and_clear;
    }
    if (result != 0 && transaction_committed == 0) {
        if (client_installed != 0 &&
            rollback_created_target(client.directory_fd, client.name) != 0) {
            rollback_failed = 1;
        }
        if (server_installed != 0 &&
            rollback_created_target(server_fd, server_name) != 0) {
            rollback_failed = 1;
        }
    }
    if (rollback_failed != 0) {
        goto close_and_clear;
    }
    if (client_staged != 0) {
        (void)unlinkat(client.directory_fd, client_temp, 0);
    }
    if (server_staged != 0) {
        (void)unlinkat(server_fd, server_temp, 0);
    }
    if (journal_exists != 0 && transaction_committed == 0) {
        (void)remove_admin_journal(server_root_fd, "add", transaction_id);
    }
close_and_clear:
    if (server_fd >= 0) {
        (void)close(server_fd);
    }
    if (client.directory_fd >= 0) {
        (void)close(client.directory_fd);
    }
    secure_memory_clear(record, sizeof(record));
    secure_memory_clear(&journal, sizeof(journal));
    secure_memory_clear(transaction_id, sizeof(transaction_id));
    secure_memory_clear(key_id, sizeof(key_id));
    return result;
}

static int enroll_inspect(int server_root_fd, const char *uid_text,
                          const char *service, FILE *output)
{
    struct ocra_secret_record record;
    char server_name[OCRA_SERVICE_MAX_LENGTH + sizeof(".conf")];
    int server_fd = -1;
    int result = -1;

    ocra_secret_record_clear(&record);
    if (snprintf(server_name, sizeof(server_name), "%s.conf", service) < 0) {
        goto cleanup;
    }
    server_fd = open_existing_server_scope(server_root_fd, uid_text);
    if (server_fd < 0 ||
        read_record_at(server_fd, server_name, server_owner_uid(),
                       server_owner_gid(), &record) != 0 ||
        fprintf(output, "uid=%s service=%s enabled=yes key_id=%s\n", uid_text,
                service, record.key_id) < 0 ||
        fflush(output) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (server_fd >= 0) {
        (void)close(server_fd);
    }
    ocra_secret_record_clear(&record);
    return result;
}

static int enroll_revoke(int server_root_fd, int rate_root_fd,
                         gid_t gid, const char *uid_text, const char *service,
                         FILE *output)
{
    struct ocra_secret_record record;
    struct revoke_journal journal;
    unsigned char serialized[OCRA_RECORD_CAPACITY];
    char server_name[OCRA_SERVICE_MAX_LENGTH + sizeof(".conf")];
    char backup_name[NAME_MAX + 1U];
    char transaction_id[OCRA_KEY_ID_HEX_LENGTH + 1U];
    size_t serialized_length = 0U;
    int server_fd = -1;
    int backup_exists = 0;
    int journal_exists = 0;
    int leave_transaction = 0;
    int result = -1;

    ocra_secret_record_clear(&record);
    (void)memset(&journal, 0, sizeof(journal));
    (void)memset(serialized, 0, sizeof(serialized));
    (void)memset(transaction_id, 0, sizeof(transaction_id));
    if (snprintf(server_name, sizeof(server_name), "%s.conf", service) < 0) {
        goto cleanup;
    }
    server_fd = open_existing_server_scope(server_root_fd, uid_text);
    if (server_fd < 0 ||
        !target_is_absent(server_root_fd, OCRA_ADMIN_JOURNAL_NAME) ||
        read_record_at(server_fd, server_name, server_owner_uid(),
                       server_owner_gid(), &record) != 0 ||
        serialize_record(&record, serialized, &serialized_length) != 0 ||
        build_transaction_id(transaction_id) != 0 ||
        format_name(backup_name, server_name, "revoked", transaction_id) != 0 ||
        !target_is_absent(server_fd, backup_name) ||
        snprintf(journal.uid_text, sizeof(journal.uid_text), "%s", uid_text) <
            0 ||
        snprintf(journal.service, sizeof(journal.service), "%s", service) < 0) {
        goto cleanup;
    }
    (void)strcpy(journal.transaction_id, transaction_id);
    (void)strcpy(journal.old_key, record.key_id);
    journal.gid = gid;
    if (write_revoke_journal(server_root_fd, &journal, "preparing") != 0) {
        goto cleanup;
    }
    journal_exists = 1;
    if (stage_record(server_fd, backup_name, server_owner_uid(),
                     server_owner_gid(), serialized, serialized_length) != 0) {
        goto cleanup;
    }
    backup_exists = 1;
    if (write_revoke_journal(server_root_fd, &journal, "prepared") != 0) {
        goto cleanup;
    }
    if (inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_REVOKE) != 0) {
        leave_transaction = 1;
        goto cleanup;
    }
    if (write_revoke_journal(server_root_fd, &journal, "committing") != 0) {
        goto cleanup;
    }
    if (inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_REVOKE) != 0) {
        leave_transaction = 1;
        goto cleanup;
    }
    if (enroll_remove_rate(rate_root_fd, uid_text, service, record.key_id) !=
        0) {
        goto cleanup;
    }
    if (inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_REVOKE) != 0) {
        leave_transaction = 1;
        goto cleanup;
    }
    if (remove_target_for_key(server_fd, server_name, server_owner_uid(),
                              server_owner_gid(), record.key_id) != 0) {
        goto cleanup;
    }
    if (inject_fault(OCRA_ENROLL_FAULT_INTERRUPT_REVOKE) != 0) {
        leave_transaction = 1;
        goto cleanup;
    }
    if (remove_transaction_artifact(server_root_fd, "revoke", transaction_id,
                                    server_fd, backup_name,
                                    &backup_exists) != 0 ||
        enroll_fsync_directory(server_fd) != 0 ||
        remove_admin_journal(server_root_fd, "revoke", transaction_id) != 0 ||
        fprintf(output,
                "ocra-enroll: revoke uid=%s service=%s completed\n",
                uid_text, service) < 0 ||
        fflush(output) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (result != 0 && leave_transaction == 0 &&
        journal_identity_matches(server_root_fd, "revoke", transaction_id)) {
        (void)recover_revoke(server_root_fd, rate_root_fd);
        goto close_and_clear_revoke;
    }
    if (result != 0 && journal_exists == 0 && backup_exists != 0) {
        (void)remove_staged(server_fd, backup_name, &backup_exists);
        (void)fsync(server_fd);
    }
close_and_clear_revoke:
    if (server_fd >= 0) {
        (void)close(server_fd);
    }
    secure_memory_clear(transaction_id, sizeof(transaction_id));
    secure_memory_clear(serialized, sizeof(serialized));
    secure_memory_clear(&journal, sizeof(journal));
    ocra_secret_record_clear(&record);
    return result;
}

static int enroll_run(int argc, char *const argv[], FILE *input, FILE *output,
                      FILE *error, int server_root_fd, int rate_root_fd)
{
    char uid_text[OCRA_UID_TEXT_MAX_LENGTH + 1U];
    uid_t uid = (uid_t)0;
    gid_t gid = (gid_t)0;
    int admin_lock_fd = -1;
    int count;
    int result = 1;

    (void)input;
    (void)rate_root_fd;
    (void)memset(uid_text, 0, sizeof(uid_text));
    if (argv == NULL || input == NULL || output == NULL || error == NULL ||
        server_root_fd < 0 || rate_root_fd < 0 || enroll_euid() != (uid_t)0 ||
        (argc != 6 && argc != 8 && argc != 9) || argv[1] == NULL ||
        argv[2] == NULL ||
        strcmp(argv[2], "--user") != 0 || argv[3] == NULL ||
        argv[4] == NULL || strcmp(argv[4], "--service") != 0 ||
        argv[5] == NULL || ocra_scope_validate_service(argv[5]) != 0 ||
        !(((argc == 8 || argc == 9) &&
           (strcmp(argv[1], "add") == 0 ||
            strcmp(argv[1], "rotate") == 0) &&
           argv[6] != NULL && strcmp(argv[6], "--client-profile") == 0 &&
           argv[7] != NULL &&
           ((argc == 8) ||
            (strcmp(argv[1], "add") == 0 && argv[8] != NULL &&
             strcmp(argv[8], "--overwrite") == 0))) ||
          (argc == 6 &&
           (strcmp(argv[1], "revoke") == 0 ||
            strcmp(argv[1], "inspect") == 0))) ||
        enroll_resolve_user(argv[3], &uid, &gid) != 0) {
        goto failure;
    }
    count = snprintf(uid_text, sizeof(uid_text), "%lu", (unsigned long)uid);
    if (count < 0 || (size_t)count >= sizeof(uid_text)) {
        goto failure;
    }
    admin_lock_fd = open_admin_lock(server_root_fd);
    if (admin_lock_fd < 0 ||
        recover_pending_transaction(server_root_fd, rate_root_fd) != 0) {
        goto failure;
    }
    if (strcmp(argv[1], "add") == 0) {
        if ((argc == 8 &&
             enroll_add(server_root_fd, uid, gid, uid_text, argv[5], argv[7],
                        output) != 0) ||
            (argc == 9 &&
             enroll_rotate(server_root_fd, rate_root_fd, uid, gid, uid_text,
                           argv[5], argv[7], input, output) != 0)) {
            goto failure;
        }
    } else if (strcmp(argv[1], "rotate") == 0) {
        if (enroll_rotate(server_root_fd, rate_root_fd, uid, gid, uid_text,
                          argv[5], argv[7], input, output) != 0) {
            goto failure;
        }
    } else if (strcmp(argv[1], "revoke") == 0) {
        if (enroll_revoke(server_root_fd, rate_root_fd, gid, uid_text, argv[5],
                          output) != 0) {
            goto failure;
        }
    } else if (enroll_inspect(server_root_fd, uid_text, argv[5], output) != 0) {
        goto failure;
    }
    result = 0;
    goto cleanup;

failure:
    (void)fprintf(error, "ocra-enroll: operation failed\n");
    (void)fflush(error);

cleanup:
    if (admin_lock_fd >= 0) {
        if (fsync(server_root_fd) != 0 || flock(admin_lock_fd, LOCK_UN) != 0 ||
            close(admin_lock_fd) != 0) {
            result = 1;
        }
    }
    secure_memory_clear(uid_text, sizeof(uid_text));
    secure_memory_clear(&uid, sizeof(uid));
    secure_memory_clear(&gid, sizeof(gid));
    return result;
}

#ifndef OCRA_ENROLL_NO_MAIN
static int system_directory_is_safe(int fd)
{
    struct stat status;

    return fstat(fd, &status) == 0 && S_ISDIR(status.st_mode) &&
           status.st_uid == (uid_t)0 && status.st_gid == (gid_t)0 &&
           (status.st_mode & 0022) == 0;
}

static int open_production_store_root(void)
{
    int root_fd = -1;
    int etc_fd = -1;
    int security_fd = -1;
    int store_fd = -1;

    root_fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root_fd < 0 || !system_directory_is_safe(root_fd)) {
        goto cleanup;
    }
    etc_fd = openat(root_fd, "etc",
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (etc_fd < 0 || !system_directory_is_safe(etc_fd)) {
        goto cleanup;
    }
    security_fd = openat(etc_fd, "security",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (security_fd < 0 || !system_directory_is_safe(security_fd)) {
        goto cleanup;
    }
    store_fd = open_or_create_server_directory(security_fd, "pam-ocra");

cleanup:
    if (security_fd >= 0) {
        (void)close(security_fd);
    }
    if (etc_fd >= 0) {
        (void)close(etc_fd);
    }
    if (root_fd >= 0) {
        (void)close(root_fd);
    }
    return store_fd;
}

static int open_production_rate_root(void)
{
    int root_fd = -1;
    int run_fd = -1;
    int parent_fd = -1;
    int rate_fd = -1;

    root_fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root_fd < 0 || !system_directory_is_safe(root_fd)) {
        goto cleanup;
    }
    run_fd = openat(root_fd, "run",
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (run_fd < 0 || !system_directory_is_safe(run_fd)) {
        goto cleanup;
    }
    parent_fd = open_or_create_server_directory(run_fd, "pam-totp-lab");
    if (parent_fd < 0) {
        goto cleanup;
    }
    rate_fd = open_or_create_server_directory(parent_fd, "ocra");

cleanup:
    if (parent_fd >= 0) {
        (void)close(parent_fd);
    }
    if (run_fd >= 0) {
        (void)close(run_fd);
    }
    if (root_fd >= 0) {
        (void)close(root_fd);
    }
    return rate_fd;
}

int main(int argc, char *argv[])
{
    int server_root_fd = -1;
    int rate_root_fd = -1;
    int result = 1;

    if (geteuid() != (uid_t)0) {
        (void)fprintf(stderr, "ocra-enroll: operation failed\n");
        return 1;
    }
    server_root_fd = open_production_store_root();
    rate_root_fd = open_production_rate_root();
    if (server_root_fd >= 0 && rate_root_fd >= 0) {
        result = enroll_run(argc, argv, stdin, stdout, stderr, server_root_fd,
                            rate_root_fd);
    } else {
        (void)fprintf(stderr, "ocra-enroll: operation failed\n");
    }
    if (rate_root_fd >= 0 && close(rate_root_fd) != 0) {
        result = 1;
    }
    if (server_root_fd >= 0 && close(server_root_fd) != 0) {
        result = 1;
    }
    return result;
}
#endif

#ifdef OCRA_TESTING
int ocra_enroll_run_at_for_tests(int argc, char *const argv[], FILE *input,
                                 FILE *output, FILE *error,
                                 int server_root_fd, int rate_root_fd)
{
    return enroll_run(argc, argv, input, output, error, server_root_fd,
                      rate_root_fd);
}

void ocra_enroll_set_random_provider_for_tests(
    ocra_enroll_random_provider provider)
{
    test_random_provider = provider;
}

void ocra_enroll_set_user_provider_for_tests(ocra_enroll_user_provider provider)
{
    test_user_provider = provider;
}

void ocra_enroll_set_euid_for_tests(uid_t euid)
{
    test_euid = euid;
    test_euid_is_set = 1;
}

void ocra_enroll_set_fault_for_tests(enum ocra_enroll_fault_operation operation,
                                     unsigned int occurrence)
{
    test_fault_operation = operation;
    test_fault_occurrence = occurrence;
    test_fault_seen = 0U;
}

void ocra_enroll_reset_test_providers(void)
{
    test_random_provider = NULL;
    test_user_provider = NULL;
    test_euid = (uid_t)0;
    test_euid_is_set = 0;
    test_fault_operation = OCRA_ENROLL_FAULT_NONE;
    test_fault_occurrence = 0U;
    test_fault_seen = 0U;
}
#endif
