/*
 * pk_manager.c - Generate partial-key files atomically.
 */
#define _GNU_SOURCE

#include "keyfile.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#define KEY_FILE ".partial_key"
#define INPUT_BUFFER_SIZE (PK_MAX_PASS_LEN + 2U)
#define TEMP_RANDOM_SIZE 8U
#define TEMP_CREATE_ATTEMPTS 128U

enum install_result {
    INSTALL_FAILED = -1,
    INSTALL_OK = 0,
    INSTALL_DURABILITY_UNCONFIRMED = 1
};

static void secure_zero(void *value, size_t length)
{
    if (value == NULL) return;
    volatile unsigned char *bytes = value;
    while (length > 0U) {
        *bytes++ = 0U;
        length--;
    }
}

static int generate_position_hash(unsigned char output[PK_HASH_LEN],
                                  const unsigned char salt[PK_SALT_LEN],
                                  int index, char character)
{
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned int digest_length = 0U;
    int result = -1;

    memset(output, 0, PK_HASH_LEN);
    if (context == NULL) return -1;

    if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(context, salt, PK_SALT_LEN) == 1 &&
        EVP_DigestUpdate(context, &index, sizeof(index)) == 1 &&
        EVP_DigestUpdate(context, &character, 1U) == 1 &&
        EVP_DigestFinal_ex(context, output, &digest_length) == 1 &&
        digest_length == PK_HASH_LEN) {
        result = 0;
    }

    EVP_MD_CTX_free(context);
    if (result != 0) secure_zero(output, PK_HASH_LEN);
    return result;
}

static int append_format(char *buffer, size_t capacity, size_t *used,
                         const char *format, ...)
{
    va_list arguments;
    int written;

    if (*used >= capacity) return -1;
    va_start(arguments, format);
    written = vsnprintf(buffer + *used, capacity - *used, format, arguments);
    va_end(arguments);
    if (written < 0 || (size_t)written >= capacity - *used) return -1;
    *used += (size_t)written;
    return 0;
}

static int append_hex(char *buffer, size_t capacity, size_t *used,
                      const unsigned char *bytes, size_t length)
{
    for (size_t i = 0U; i < length; i++) {
        if (append_format(buffer, capacity, used, "%02x",
                          (unsigned int)bytes[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

static int serialize_key_file(const char *password, size_t password_length,
                              const unsigned char salt[PK_SALT_LEN],
                              char output[PK_MAX_FILE_SIZE + 1U],
                              size_t *output_length)
{
    unsigned char hash[PK_HASH_LEN];
    size_t used = 0U;
    int result = -1;

    memset(hash, 0, sizeof(hash));
    memset(output, 0, PK_MAX_FILE_SIZE + 1U);
    if (append_format(output, PK_MAX_FILE_SIZE + 1U, &used, "%zu|",
                      password_length) != 0 ||
        append_hex(output, PK_MAX_FILE_SIZE + 1U, &used, salt,
                   PK_SALT_LEN) != 0 ||
        append_format(output, PK_MAX_FILE_SIZE + 1U, &used, "|") != 0) {
        goto cleanup;
    }

    for (size_t i = 0U; i < password_length; i++) {
        if (generate_position_hash(hash, salt, (int)i, password[i]) != 0 ||
            append_hex(output, PK_MAX_FILE_SIZE + 1U, &used, hash,
                       PK_HASH_LEN) != 0 ||
            (i + 1U < password_length &&
             append_format(output, PK_MAX_FILE_SIZE + 1U, &used, "|") != 0)) {
            goto cleanup;
        }
        secure_zero(hash, sizeof(hash));
    }
    if (append_format(output, PK_MAX_FILE_SIZE + 1U, &used, "\n") != 0 ||
        used > PK_MAX_FILE_SIZE) {
        goto cleanup;
    }

    *output_length = used;
    result = 0;

cleanup:
    secure_zero(hash, sizeof(hash));
    if (result != 0) secure_zero(output, PK_MAX_FILE_SIZE + 1U);
    return result;
}

static int write_all(int descriptor, const char *buffer, size_t length)
{
    size_t written = 0U;

    while (written < length) {
        ssize_t count = write(descriptor, buffer + written, length - written);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (count == 0) return -1;
        written += (size_t)count;
    }
    return 0;
}

static int read_password(char *buffer, size_t buffer_size)
{
    struct termios original_settings;
    struct termios hidden_settings;
    sigset_t blocked_signals;
    sigset_t original_mask;
    int input_fd = fileno(stdin);
    int terminal_input = isatty(input_fd);
    int signals_blocked = 0;
    int echo_disabled = 0;
    int result = -1;

    if (terminal_input) {
        if (sigemptyset(&blocked_signals) != 0 ||
            sigaddset(&blocked_signals, SIGINT) != 0 ||
            sigaddset(&blocked_signals, SIGTERM) != 0 ||
            sigaddset(&blocked_signals, SIGHUP) != 0 ||
            sigaddset(&blocked_signals, SIGQUIT) != 0 ||
            sigaddset(&blocked_signals, SIGTSTP) != 0 ||
            sigprocmask(SIG_BLOCK, &blocked_signals, &original_mask) != 0) {
            return -1;
        }
        signals_blocked = 1;
        if (tcgetattr(input_fd, &original_settings) != 0) goto cleanup;
        hidden_settings = original_settings;
        hidden_settings.c_lflag &= (tcflag_t)~ECHO;
        if (tcsetattr(input_fd, TCSAFLUSH, &hidden_settings) != 0) {
            goto cleanup;
        }
        echo_disabled = 1;
    }

    if (fgets(buffer, (int)buffer_size, stdin) != NULL) result = 0;

cleanup:
    if (echo_disabled) {
        if (tcsetattr(input_fd, TCSANOW, &original_settings) != 0) result = -1;
        (void)fputc('\n', stderr);
    }
    if (signals_blocked &&
        sigprocmask(SIG_SETMASK, &original_mask, NULL) != 0) {
        result = -1;
    }
    return result;
}

static int create_temporary_file(int directory_fd, char *name,
                                 size_t name_size)
{
    unsigned char random_bytes[TEMP_RANDOM_SIZE];
    int descriptor = -1;

    memset(random_bytes, 0, sizeof(random_bytes));
    for (size_t attempt = 0U; attempt < TEMP_CREATE_ATTEMPTS; attempt++) {
        size_t used = 0U;
        memset(name, 0, name_size);
        if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1 ||
            append_format(name, name_size, &used, "%s.tmp.", KEY_FILE) != 0 ||
            append_hex(name, name_size, &used, random_bytes,
                       sizeof(random_bytes)) != 0) {
            break;
        }
        descriptor = openat(directory_fd, name,
                            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                                O_CLOEXEC,
                            (mode_t)0600);
        if (descriptor >= 0 || errno != EEXIST) break;
    }
    secure_zero(random_bytes, sizeof(random_bytes));
    return descriptor;
}

static int sync_directory(int directory_fd)
{
#ifdef PK_MANAGER_TESTING
    const char *inject_failure = getenv("PK_MANAGER_TEST_FAIL_DIR_FSYNC");
    if (inject_failure != NULL && strcmp(inject_failure, "1") == 0) {
        errno = EIO;
        return -1;
    }
#endif
    return fsync(directory_fd);
}

static int install_key_file(const char *home_directory, const char *serialized,
                            size_t serialized_length)
{
    char temporary_name[64];
    int directory_fd = -1;
    int temporary_fd = -1;
    int result = INSTALL_FAILED;
    mode_t old_mask = umask((mode_t)0077);

    memset(temporary_name, 0, sizeof(temporary_name));
    directory_fd = open(home_directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) goto cleanup;

    temporary_fd = create_temporary_file(directory_fd, temporary_name,
                                         sizeof(temporary_name));
    if (temporary_fd < 0) goto cleanup;
    if (fchmod(temporary_fd, (mode_t)0600) != 0 ||
        write_all(temporary_fd, serialized, serialized_length) != 0 ||
        fsync(temporary_fd) != 0) {
        goto cleanup;
    }
    if (close(temporary_fd) != 0) {
        temporary_fd = -1;
        goto cleanup;
    }
    temporary_fd = -1;

    if (renameat(directory_fd, temporary_name, directory_fd, KEY_FILE) != 0) {
        goto cleanup;
    }
    temporary_name[0] = '\0';
    if (sync_directory(directory_fd) != 0) {
        /*
         * renameat() has already replaced the key.  Reporting a plain install
         * failure would incorrectly suggest that the previous key remains.
         */
        result = INSTALL_DURABILITY_UNCONFIRMED;
        goto cleanup;
    }
    result = INSTALL_OK;

cleanup:
    if (temporary_fd >= 0) close(temporary_fd);
    if (directory_fd >= 0) {
        if (temporary_name[0] != '\0') {
            (void)unlinkat(directory_fd, temporary_name, 0);
        }
        close(directory_fd);
    }
    umask(old_mask);
    secure_zero(temporary_name, sizeof(temporary_name));
    return result;
}

int main(void)
{
    char password[INPUT_BUFFER_SIZE];
    char serialized[PK_MAX_FILE_SIZE + 1U];
    unsigned char salt[PK_SALT_LEN];
    const char *home_directory = getenv("HOME");
    size_t password_length = 0U;
    size_t serialized_length = 0U;
    int install_status;
    int result = EXIT_FAILURE;

    memset(password, 0, sizeof(password));
    memset(serialized, 0, sizeof(serialized));
    memset(salt, 0, sizeof(salt));

    if (home_directory == NULL || home_directory[0] != '/') {
        fputs("Error: HOME must name an absolute directory.\n", stderr);
        goto cleanup;
    }

    printf("=== Partial Key Setup (Secure Edition) ===\n");
    printf("Define your Banking-Style Password (%u-%u chars): ",
           (unsigned int)PK_MIN_PASS_LEN, (unsigned int)PK_MAX_PASS_LEN);
    if (fflush(stdout) != 0 || read_password(password, sizeof(password)) != 0) {
        fputs("Error: failed to read the password.\n", stderr);
        goto cleanup;
    }

    password_length = strcspn(password, "\r\n");
    if (password[password_length] == '\r' || password[password_length] == '\n') {
        password[password_length] = '\0';
    } else if (!feof(stdin)) {
        fputs("Error: password exceeds the maximum length.\n", stderr);
        goto cleanup;
    }
    if (password_length < PK_MIN_PASS_LEN ||
        password_length > PK_MAX_PASS_LEN) {
        fputs("Error: password length is outside the accepted range.\n",
              stderr);
        goto cleanup;
    }

    if (RAND_bytes(salt, sizeof(salt)) != 1 ||
        serialize_key_file(password, password_length, salt, serialized,
                           &serialized_length) != 0) {
        fputs("Error: cryptographic key generation failed.\n", stderr);
        goto cleanup;
    }
    install_status = install_key_file(home_directory, serialized,
                                      serialized_length);
    if (install_status == INSTALL_DURABILITY_UNCONFIRMED) {
        fputs("Error: the key file was replaced, but directory durability "
              "could not be confirmed; do not assume the previous key "
              "remains installed.\n",
              stderr);
        goto cleanup;
    }
    if (install_status != INSTALL_OK) {
        fputs("Error: the key file could not be installed atomically.\n",
              stderr);
        goto cleanup;
    }

    printf("[OK] Key stored in %s/%s with permissions 0600.\n",
           home_directory, KEY_FILE);
    result = EXIT_SUCCESS;

cleanup:
    secure_zero(password, sizeof(password));
    secure_zero(serialized, sizeof(serialized));
    secure_zero(salt, sizeof(salt));
    return result;
}
