#define _GNU_SOURCE

#include "../pam_partial_key/keyfile.h"
#include "../pam_schedule_totp_override/schedule.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#define KEY_DIRECTORY "/etc/security/pam-schedule-partial-key"

static const char *key_directory(void)
{
#ifdef SPK_MANAGER_TESTING
    const char *override = getenv("SPK_MANAGER_TEST_DIRECTORY");
    if (override != NULL && override[0] == '/') return override;
#endif
    return KEY_DIRECTORY;
}

static void wipe(void *value, size_t length)
{
    volatile unsigned char *p = value;
    if (value == NULL) return;
    while (length-- > 0U) *p++ = 0U;
}

static int append(char *out, size_t capacity, size_t *used,
                  const char *format, ...)
{
    va_list args;
    int count;
    if (*used >= capacity) return -1;
    va_start(args, format);
    count = vsnprintf(out + *used, capacity - *used, format, args);
    va_end(args);
    if (count < 0 || (size_t)count >= capacity - *used) return -1;
    *used += (size_t)count;
    return 0;
}

static int append_hex(char *out, size_t capacity, size_t *used,
                      const unsigned char *bytes, size_t length)
{
    for (size_t i = 0U; i < length; i++) {
        if (append(out, capacity, used, "%02x", bytes[i]) != 0) return -1;
    }
    return 0;
}

static int read_hidden(char *out, size_t capacity)
{
    struct termios old;
    struct termios hidden;
    int terminal = isatty(STDIN_FILENO);
    int changed = 0;
    int result = -1;
    if (terminal != 0) {
        if (tcgetattr(STDIN_FILENO, &old) != 0) return -1;
        hidden = old;
        hidden.c_lflag &= (tcflag_t)~ECHO;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) return -1;
        changed = 1;
    }
    if (fgets(out, (int)capacity, stdin) != NULL) result = 0;
    if (changed != 0) {
        if (tcsetattr(STDIN_FILENO, TCSANOW, &old) != 0) result = -1;
        (void)fputc('\n', stderr);
    }
    return result;
}

static int serialize(const char *password, size_t length, char *out,
                     size_t capacity, size_t *length_out)
{
    unsigned char salt[PK_SALT_LEN];
    unsigned char hash[PK_HASH_LEN];
    size_t used = 0U;
    int result = -1;
    memset(salt, 0, sizeof(salt));
    memset(hash, 0, sizeof(hash));
    if (RAND_bytes(salt, sizeof(salt)) != 1 ||
        append(out, capacity, &used, "%zu|", length) != 0 ||
        append_hex(out, capacity, &used, salt, sizeof(salt)) != 0 ||
        append(out, capacity, &used, "|") != 0) {
        goto cleanup;
    }
    for (size_t i = 0U; i < length; i++) {
        if (pk_hash_position(hash, salt, (int)i, password[i]) != 0 ||
            append_hex(out, capacity, &used, hash, sizeof(hash)) != 0 ||
            (i + 1U < length && append(out, capacity, &used, "|") != 0)) {
            goto cleanup;
        }
        wipe(hash, sizeof(hash));
    }
    if (append(out, capacity, &used, "\n") != 0) goto cleanup;
    *length_out = used;
    result = 0;

cleanup:
    wipe(salt, sizeof(salt));
    wipe(hash, sizeof(hash));
    return result;
}

static int install_key(const char *authorizer, const char *data, size_t length)
{
    unsigned char random[8];
    char target[64];
    char temporary[80];
    int directory_fd = -1;
    int fd = -1;
    int result = -1;
    struct stat directory_status;
    int target_count;
    int temp_count;
    size_t written = 0U;

    target_count = snprintf(target, sizeof(target), "%s.pkey", authorizer);
    if (target_count < 0 || (size_t)target_count >= sizeof(target) ||
        RAND_bytes(random, sizeof(random)) != 1) {
        return -1;
    }
    temp_count = snprintf(temporary, sizeof(temporary),
                          ".%s.%02x%02x%02x%02x%02x%02x%02x%02x.tmp",
                          authorizer, random[0], random[1], random[2], random[3],
                          random[4], random[5], random[6], random[7]);
    wipe(random, sizeof(random));
    if (temp_count < 0 || (size_t)temp_count >= sizeof(temporary)) return -1;
    directory_fd = open(key_directory(),
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0 || fstat(directory_fd, &directory_status) != 0 ||
        !S_ISDIR(directory_status.st_mode) ||
        directory_status.st_uid != geteuid() ||
        (directory_status.st_mode & (mode_t)0077) != 0) {
        if (directory_fd >= 0) close(directory_fd);
        return -1;
    }
    fd = openat(directory_fd, temporary,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                (mode_t)0600);
    if (fd < 0) goto cleanup;
    while (written < length) {
        ssize_t count = write(fd, data + written, length - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) goto cleanup;
        written += (size_t)count;
    }
    if (fchmod(fd, (mode_t)0600) != 0 || fsync(fd) != 0 || close(fd) != 0) {
        fd = -1;
        goto cleanup;
    }
    fd = -1;
    if (renameat(directory_fd, temporary, directory_fd, target) != 0 ||
        fsync(directory_fd) != 0) {
        goto cleanup;
    }
    temporary[0] = '\0';
    result = 0;

cleanup:
    if (fd >= 0) close(fd);
    if (temporary[0] != '\0') (void)unlinkat(directory_fd, temporary, 0);
    close(directory_fd);
    wipe(temporary, sizeof(temporary));
    return result;
}

int main(int argc, char **argv)
{
    char password[PK_MAX_PASS_LEN + 2U];
    char serialized[PK_MAX_FILE_SIZE + 1U];
    size_t length;
    size_t serialized_length = 0U;
    int result = EXIT_FAILURE;
    memset(password, 0, sizeof(password));
    memset(serialized, 0, sizeof(serialized));
    if (argc != 2 ||
#ifndef SPK_MANAGER_TESTING
        geteuid() != (uid_t)0 ||
#endif
        pso_validate_authorizer_name(argv[1]) != 0) {
        fputs("usage: sudo schedule_partial_key_manager AUTHORIZER\n", stderr);
        goto cleanup;
    }
    fprintf(stderr, "Clave docente para %s (%u-%u caracteres): ", argv[1],
            (unsigned int)PK_MIN_PASS_LEN, (unsigned int)PK_MAX_PASS_LEN);
    if (read_hidden(password, sizeof(password)) != 0) goto cleanup;
    length = strcspn(password, "\r\n");
    if (length < PK_MIN_PASS_LEN || length > PK_MAX_PASS_LEN ||
        (password[length] == '\0' && !feof(stdin))) {
        fputs("Clave fuera de los limites permitidos.\n", stderr);
        goto cleanup;
    }
    password[length] = '\0';
    if (serialize(password, length, serialized, sizeof(serialized),
                  &serialized_length) != 0 ||
        install_key(argv[1], serialized, serialized_length) != 0) {
        fputs("No se pudo instalar la clave de forma atomica.\n", stderr);
        goto cleanup;
    }
    fprintf(stdout, "Clave de %s instalada correctamente.\n", argv[1]);
    result = EXIT_SUCCESS;

cleanup:
    wipe(password, sizeof(password));
    wipe(serialized, sizeof(serialized));
    return result;
}
