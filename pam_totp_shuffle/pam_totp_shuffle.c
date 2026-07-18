#define _GNU_SOURCE

#include "secret.h"
#include "shuffle.h"
#include "../pam_common/totp_replay.h"

#include <liboath/oath.h>
#include <pthread.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#define PTS_TOTP_STEP 30U
#define PTS_TOTP_WINDOW 1U
#define PTS_FAIL_DELAY_US 3000000U
#define PTS_INPUT_SCAN_LIMIT 64U
#define PTS_REPLAY_TAG "pam_totp_shuffle"
#define PTS_FAKE_SECRET "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

static pthread_once_t oath_once = PTHREAD_ONCE_INIT;
static int oath_status = OATH_CRYPTO_ERROR;

static void pts_initialize_oath(void)
{
    oath_status = oath_init();
}

static int pts_ensure_oath(void)
{
    return pthread_once(&oath_once, pts_initialize_oath) == 0 &&
                   oath_status == OATH_OK
               ? 0
               : -1;
}

static void pts_secure_free(char **buffer, size_t length)
{
    if (buffer == NULL || *buffer == NULL) return;
    pts_secure_memzero(*buffer, length);
    free(*buffer);
    *buffer = NULL;
}

static int pts_parse_options(int argc, const char **argv, int *nullok_out)
{
    int nullok = 0;

    if (nullok_out == NULL || argc < 0) return -1;
    for (int i = 0; i < argc; i++) {
        if (argv == NULL || argv[i] == NULL) return -1;
        if (strcmp(argv[i], "nullok") == 0) {
            nullok = 1;
        } else {
            return -1;
        }
    }
    *nullok_out = nullok;
    return 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv)
{
    const char *username = NULL;
    char secret_base32[PTS_MAX_SECRET_LENGTH + 1U] = {0};
    char prompt[PTS_PROMPT_MAX] = {0};
    unsigned int order[PTS_CODE_LENGTH] = {0};
    char restored_code[PTS_CODE_LENGTH + 1U] = {0};
    char *response = NULL;
    char *secret_binary = NULL;
    size_t secret_binary_length = 0U;
    size_t response_length = 0U;
    uid_t user_id = (uid_t)0;
    uint64_t otp_counter = UINT64_C(0);
    int nullok = 0;
    int fake_mode = 0;
    int result = PAM_AUTH_ERR;
    int secret_status;
    int oath_result;
    time_t now;

    (void)flags;

    if (pamh == NULL || pts_parse_options(argc, argv, &nullok) != 0) {
        syslog(LOG_ERR, "pam_totp_shuffle: unsupported module option");
        return PAM_AUTH_ERR;
    }
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || username == NULL ||
        pts_ensure_oath() != 0 || pts_generate_permutation(order) != 0 ||
        pts_format_prompt(order, prompt, sizeof(prompt)) != 0) {
        goto cleanup;
    }

    secret_status = pts_get_user_secret(username, secret_base32,
                                        sizeof(secret_base32), &user_id);
    if (secret_status != PTS_SECRET_OK) {
        if (secret_status == PTS_SECRET_NOT_FOUND && nullok) {
            result = PAM_IGNORE;
            goto cleanup;
        }
        fake_mode = 1;
        memcpy(secret_base32, PTS_FAKE_SECRET, sizeof(PTS_FAKE_SECRET));
    }

    result = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &response, "%s", prompt);
    if (response != NULL) response_length = strnlen(response, PTS_INPUT_SCAN_LIMIT);
    if (result != PAM_SUCCESS || response == NULL ||
        response_length != PTS_CODE_LENGTH ||
        pts_restore_code(response, response_length, order, restored_code) != 0) {
        result = PAM_AUTH_ERR;
        goto cleanup;
    }

    oath_result = oath_base32_decode(secret_base32, strlen(secret_base32),
                                     &secret_binary, &secret_binary_length);
    pts_secure_memzero(secret_base32, sizeof(secret_base32));
    if (oath_result != OATH_OK) {
        if (!fake_mode) syslog(LOG_ERR, "pam_totp_shuffle: invalid stored secret");
        result = PAM_AUTH_ERR;
        goto cleanup;
    }

    now = time(NULL);
    if (now == (time_t)-1) {
        result = PAM_AUTH_ERR;
        goto cleanup;
    }

    oath_result = oath_totp_validate3(secret_binary, secret_binary_length, now,
                                      PTS_TOTP_STEP, 0, PTS_TOTP_WINDOW, NULL,
                                      &otp_counter, restored_code);
    if (oath_result >= 0 && !fake_mode) {
        int replay_result =
            totp_replay_check_and_store(PTS_REPLAY_TAG, user_id, otp_counter);
        if (replay_result == TOTP_REPLAY_ACCEPTED) {
            result = PAM_SUCCESS;
        } else {
            syslog(replay_result == TOTP_REPLAY_DETECTED ? LOG_NOTICE : LOG_ERR,
                   "pam_totp_shuffle: rejected consumed TOTP counter");
            result = PAM_AUTH_ERR;
        }
    } else {
        if (!fake_mode) syslog(LOG_NOTICE, "pam_totp_shuffle: invalid TOTP attempt");
        result = PAM_AUTH_ERR;
    }

cleanup:
    pts_secure_memzero(secret_base32, sizeof(secret_base32));
    pts_secure_memzero(prompt, sizeof(prompt));
    pts_secure_memzero(order, sizeof(order));
    pts_secure_memzero(restored_code, sizeof(restored_code));
    if (secret_binary != NULL) {
        pts_secure_memzero(secret_binary, secret_binary_length);
        free(secret_binary);
    }
    if (response != NULL) {
        size_t wipe_length = response_length < PTS_INPUT_SCAN_LIMIT
                                 ? response_length + 1U
                                 : PTS_INPUT_SCAN_LIMIT;
        pts_secure_free(&response, wipe_length);
    }
    if (result != PAM_SUCCESS && result != PAM_IGNORE) {
        (void)pam_fail_delay(pamh, PTS_FAIL_DELAY_US);
    }
    return result;
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
