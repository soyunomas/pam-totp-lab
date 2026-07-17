/*
 * pam_partial_key.c
 * Memory-safe parser and bounded challenge handling for a partial-key PAM.
 */
#define _GNU_SOURCE
#define _DEFAULT_SOURCE

#include "keyfile.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pwd.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define KEY_FILE ".partial_key"
#define CHALLENGE_COUNT 3U
#define MAX_RANDOM_ATTEMPTS 128U
#define MAX_PASSWD_BUFFER (1024U * 1024U)

static void secure_zero(void *value, size_t length)
{
    if (value == NULL) {
        return;
    }

    volatile unsigned char *bytes = value;
    while (length > 0U) {
        *bytes++ = 0U;
        length--;
    }
}

static int calc_hash(unsigned char output[PK_HASH_LEN],
                     const unsigned char salt[PK_SALT_LEN], int index,
                     char character)
{
    EVP_MD_CTX *context = NULL;
    unsigned int digest_length = 0U;
    int result = -1;

    memset(output, 0, PK_HASH_LEN);
    context = EVP_MD_CTX_new();
    if (context == NULL) {
        return -1;
    }

    if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(context, salt, PK_SALT_LEN) == 1 &&
        EVP_DigestUpdate(context, &index, sizeof(index)) == 1 &&
        EVP_DigestUpdate(context, &character, 1U) == 1 &&
        EVP_DigestFinal_ex(context, output, &digest_length) == 1 &&
        digest_length == PK_HASH_LEN) {
        result = 0;
    }

    EVP_MD_CTX_free(context);
    if (result != 0) {
        secure_zero(output, PK_HASH_LEN);
    }
    return result;
}

static int write_all(int descriptor, const unsigned char *buffer,
                     size_t length)
{
    size_t written = 0U;

    while (written < length) {
        ssize_t result = write(descriptor, buffer + written, length - written);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (result == 0) {
            return -1;
        }
        written += (size_t)result;
    }
    return 0;
}

static int child_send_key_file(int output_fd, const char *path, uid_t owner)
{
    unsigned char buffer[PK_MAX_FILE_SIZE + 1U];
    struct stat status;
    size_t total = 0U;
    int descriptor = -1;
    int result = -1;

    memset(buffer, 0, sizeof(buffer));
    descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (descriptor < 0) {
        goto cleanup;
    }

    if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_uid != owner || (status.st_mode & 0077) != 0) {
        goto cleanup;
    }

    while (total < sizeof(buffer)) {
        ssize_t count = read(descriptor, buffer + total,
                             sizeof(buffer) - total);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            goto cleanup;
        }
        if (count == 0) {
            break;
        }
        total += (size_t)count;
    }

    if (total == 0U || total > PK_MAX_FILE_SIZE ||
        write_all(output_fd, buffer, total) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (descriptor >= 0) {
        close(descriptor);
    }
    secure_zero(buffer, sizeof(buffer));
    return result;
}

static int wait_for_child(pid_t child, int *status_out)
{
    pid_t result;
    do {
        result = waitpid(child, status_out, 0);
    } while (result < 0 && errno == EINTR);
    return result == child ? 0 : -1;
}

static int get_user_key_data(const char *username,
                             struct pk_key_data *key_data)
{
    unsigned char serialized[PK_MAX_FILE_SIZE + 1U];
    struct passwd password_entry;
    struct passwd *password_result = NULL;
    char path[PATH_MAX];
    char *password_buffer = NULL;
    long configured_size;
    size_t password_buffer_size;
    size_t total = 0U;
    uid_t user_id;
    gid_t group_id;
    int pipe_fds[2] = {-1, -1};
    int child_status = 0;
    int read_failed = 0;
    int result = -1;
    int path_length;
    pid_t child = -1;

    if (username == NULL || key_data == NULL) {
        return -1;
    }
    pk_key_data_clear(key_data);
    memset(serialized, 0, sizeof(serialized));
    memset(&password_entry, 0, sizeof(password_entry));

    configured_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (configured_size < 0) {
        configured_size = 16384;
    }
    if (configured_size <= 0 ||
        (unsigned long)configured_size > MAX_PASSWD_BUFFER) {
        return -1;
    }
    password_buffer_size = (size_t)configured_size;
    password_buffer = calloc(1U, password_buffer_size);
    if (password_buffer == NULL) {
        return -1;
    }

    if (getpwnam_r(username, &password_entry, password_buffer,
                   password_buffer_size, &password_result) != 0 ||
        password_result == NULL || password_entry.pw_dir == NULL) {
        goto cleanup;
    }

    path_length = snprintf(path, sizeof(path), "%s/%s",
                           password_entry.pw_dir, KEY_FILE);
    if (path_length < 0 || (size_t)path_length >= sizeof(path)) {
        goto cleanup;
    }
    user_id = password_entry.pw_uid;
    group_id = password_entry.pw_gid;

    secure_zero(password_buffer, password_buffer_size);
    free(password_buffer);
    password_buffer = NULL;

    if (pipe2(pipe_fds, O_CLOEXEC) != 0) {
        goto cleanup;
    }

    child = fork();
    if (child < 0) {
        goto cleanup;
    }

    if (child == 0) {
        close(pipe_fds[0]);
        if (initgroups(username, group_id) != 0 || setgid(group_id) != 0 ||
            setuid(user_id) != 0) {
            _exit(EXIT_FAILURE);
        }
        int child_result = child_send_key_file(pipe_fds[1], path, user_id);
        close(pipe_fds[1]);
        _exit(child_result == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    close(pipe_fds[1]);
    pipe_fds[1] = -1;

    while (total < sizeof(serialized)) {
        ssize_t count = read(pipe_fds[0], serialized + total,
                             sizeof(serialized) - total);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            read_failed = 1;
            break;
        }
        if (count == 0) {
            break;
        }
        total += (size_t)count;
    }

    close(pipe_fds[0]);
    pipe_fds[0] = -1;
    if (wait_for_child(child, &child_status) != 0) {
        child = -1;
        goto cleanup;
    }
    child = -1;

    if (read_failed || total == 0U || total > PK_MAX_FILE_SIZE ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != EXIT_SUCCESS) {
        goto cleanup;
    }

    if (pk_parse_key_data(serialized, total, key_data) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (pipe_fds[0] >= 0) {
        close(pipe_fds[0]);
    }
    if (pipe_fds[1] >= 0) {
        close(pipe_fds[1]);
    }
    if (child > 0) {
        (void)wait_for_child(child, &child_status);
    }
    if (password_buffer != NULL) {
        secure_zero(password_buffer, password_buffer_size);
        free(password_buffer);
    }
    secure_zero(serialized, sizeof(serialized));
    if (result != 0) {
        pk_key_data_clear(key_data);
    }
    return result;
}

static int random_below(size_t upper_bound, size_t *value_out)
{
    unsigned int range;
    unsigned int limit;
    unsigned char random_byte;

    if (upper_bound == 0U || upper_bound > 256U || value_out == NULL) {
        return -1;
    }
    range = (unsigned int)upper_bound;
    limit = 256U - (256U % range);

    for (size_t attempt = 0U; attempt < MAX_RANDOM_ATTEMPTS; attempt++) {
        if (RAND_bytes(&random_byte, 1) != 1) {
            return -1;
        }
        if ((unsigned int)random_byte < limit) {
            *value_out = (size_t)((unsigned int)random_byte % range);
            return 0;
        }
    }
    return -1;
}

static int select_unique_indices(size_t pass_len,
                                 size_t indices[CHALLENGE_COUNT])
{
    if (pass_len < CHALLENGE_COUNT || pass_len > PK_MAX_PASS_LEN) {
        return -1;
    }

    for (size_t i = 0U; i < CHALLENGE_COUNT; i++) {
        int selected = 0;
        for (size_t attempt = 0U; attempt < MAX_RANDOM_ATTEMPTS; attempt++) {
            size_t candidate;
            int unique = 1;
            if (random_below(pass_len, &candidate) != 0) {
                return -1;
            }
            for (size_t previous = 0U; previous < i; previous++) {
                if (indices[previous] == candidate) {
                    unique = 0;
                }
            }
            if (unique) {
                indices[i] = candidate;
                selected = 1;
                break;
            }
        }
        if (!selected) {
            return -1;
        }
    }
    return 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv)
{
    const char *user = NULL;
    struct pk_key_data key_data;
    size_t indices[CHALLENGE_COUNT] = {0U};
    char prompt[128] = {0};
    char *response = NULL;
    char clean_response[CHALLENGE_COUNT + 1U] = {0};
    unsigned char computed_hash[PK_HASH_LEN] = {0U};
    size_t clean_length = 0U;
    size_t response_length = 0U;
    unsigned int mismatch = 0U;
    int retval = PAM_AUTH_ERR;

    (void)flags;
    (void)argc;
    (void)argv;
    pk_key_data_clear(&key_data);

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        return PAM_AUTH_ERR;
    }
    if (get_user_key_data(user, &key_data) != 0) {
        goto cleanup;
    }
    if (select_unique_indices(key_data.pass_len, indices) != 0) {
        goto cleanup;
    }

    int prompt_length = snprintf(prompt, sizeof(prompt),
                                 "Posiciones [%zu] [%zu] [%zu]: ",
                                 indices[0] + 1U, indices[1] + 1U,
                                 indices[2] + 1U);
    if (prompt_length < 0 || (size_t)prompt_length >= sizeof(prompt)) {
        goto cleanup;
    }

    if (pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &response, "%s", prompt) !=
            PAM_SUCCESS ||
        response == NULL) {
        goto cleanup;
    }

    response_length = strnlen(response, PAM_MAX_RESP_SIZE);
    if (response_length == PAM_MAX_RESP_SIZE) {
        goto cleanup;
    }
    for (size_t i = 0U; i < response_length; i++) {
        if (!isspace((unsigned char)response[i])) {
            if (clean_length >= CHALLENGE_COUNT) {
                goto cleanup;
            }
            clean_response[clean_length++] = response[i];
        }
    }
    if (clean_length != CHALLENGE_COUNT) {
        goto cleanup;
    }

    for (size_t i = 0U; i < CHALLENGE_COUNT; i++) {
        if (calc_hash(computed_hash, key_data.salt, (int)indices[i],
                      clean_response[i]) != 0) {
            goto cleanup;
        }
        mismatch |= (unsigned int)CRYPTO_memcmp(
            computed_hash, key_data.hashes[indices[i]], PK_HASH_LEN);
        secure_zero(computed_hash, sizeof(computed_hash));
    }

    if (mismatch == 0U) {
        retval = PAM_SUCCESS;
    }

cleanup:
    if (response != NULL) {
        size_t wipe_length = strnlen(response, PAM_MAX_RESP_SIZE);
        secure_zero(response, wipe_length);
        free(response);
    }
    secure_zero(clean_response, sizeof(clean_response));
    secure_zero(computed_hash, sizeof(computed_hash));
    secure_zero(prompt, sizeof(prompt));
    pk_key_data_clear(&key_data);

    if (retval != PAM_SUCCESS) {
        (void)pam_fail_delay(pamh, 2000000U);
    }
    return retval;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
