#define _GNU_SOURCE

#include "config.h"
#include "secret.h"
#include "slot_policy.h"
#include "../pam_common/totp_replay.h"

#include <liboath/oath.h>
#include <limits.h>
#include <pthread.h>
#include <pwd.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define PTSC_TOTP_STEP 30U
#define PTSC_TOTP_WINDOW 1U
#define PTSC_FAIL_DELAY 3000000U
#define PTSC_OTP_DIGITS 6U
#define PTSC_FAKE_SECRET "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

static pthread_once_t oath_once = PTHREAD_ONCE_INIT;
static int oath_status = OATH_CRYPTO_ERROR;

static void initialize_oath(void)
{
    oath_status = oath_init();
}

static int ensure_oath(void)
{
    return pthread_once(&oath_once, initialize_oath) == 0 &&
                   oath_status == OATH_OK
               ? 0
               : -1;
}

static int resolve_user(const char *username, uid_t *uid_out,
                        char *home_out, size_t home_capacity)
{
    long configured_size;
    size_t buffer_size;
    char *buffer = NULL;
    struct passwd pwd;
    struct passwd *result = NULL;
    int status = -1;

    if (username == NULL || uid_out == NULL || home_out == NULL ||
        home_capacity == 0U) {
        return -1;
    }

    configured_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    buffer_size = configured_size > 0 ? (size_t)configured_size : 16384U;
    if (buffer_size > (size_t)1048576U) {
        return -1;
    }

    buffer = calloc(1U, buffer_size);
    if (buffer == NULL) {
        return -1;
    }

    if (getpwnam_r(username, &pwd, buffer, buffer_size, &result) != 0 ||
        result == NULL || pwd.pw_dir == NULL || pwd.pw_dir[0] != '/' ||
        strnlen(pwd.pw_dir, home_capacity) >= home_capacity) {
        goto cleanup;
    }

    *uid_out = pwd.pw_uid;
    memcpy(home_out, pwd.pw_dir, strlen(pwd.pw_dir) + 1U);
    status = 0;

cleanup:
    ptsc_secure_memzero(buffer, buffer_size);
    free(buffer);
    return status;
}

static int validate_otp(const char *otp, size_t length)
{
    if (otp == NULL || length != PTSC_OTP_DIGITS) {
        return -1;
    }
    for (size_t i = 0U; i < length; i++) {
        if (otp[i] < '0' || otp[i] > '9') {
            return -1;
        }
    }
    return 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv)
{
    const char *username = NULL;
    const struct ptsc_slot *slot = NULL;
    size_t slot_count = 0U;
    size_t slot_index = 0U;
    uid_t user_id = (uid_t)0;
    char home[PATH_MAX];
    char secret_base32[PTSC_MAX_SECRET_LEN + 1U];
    char prompt[48];
    char *otp_input = NULL;
    size_t otp_length = 0U;
    char *secret_binary = NULL;
    size_t secret_binary_length = 0U;
    uint64_t counter = UINT64_C(0);
    int fake_mode = 0;
    int retval = PAM_AUTH_ERR;
    int rc;
    int prompt_length;
    time_t now;

    (void)flags;
    memset(home, 0, sizeof(home));
    memset(secret_base32, 0, sizeof(secret_base32));

    if (ptsc_parse_options(argc, argv, &slot_count) != 0) {
        return PAM_SERVICE_ERR;
    }
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS ||
        username == NULL || ensure_oath() != 0 ||
        ptsc_random_index(slot_count, &slot_index) != 0) {
        return PAM_AUTH_ERR;
    }

    slot = ptsc_slot_by_index(slot_index);
    if (slot == NULL) {
        return PAM_AUTH_ERR;
    }

    if (resolve_user(username, &user_id, home, sizeof(home)) != 0 ||
        ptsc_read_slot_secret(home, user_id, slot_index, secret_base32,
                              sizeof(secret_base32)) != PTSC_SECRET_OK) {
        fake_mode = 1;
        memcpy(secret_base32, PTSC_FAKE_SECRET, sizeof(PTSC_FAKE_SECRET));
    }

    prompt_length = snprintf(prompt, sizeof(prompt), "TOTP del slot %s: ",
                             slot->prompt_label);
    if (prompt_length < 0 || (size_t)prompt_length >= sizeof(prompt)) {
        goto cleanup;
    }
    retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &otp_input, "%s", prompt);
    if (otp_input != NULL) {
        otp_length = strnlen(otp_input, PAM_MAX_RESP_SIZE);
    }
    if (retval != PAM_SUCCESS || validate_otp(otp_input, otp_length) != 0) {
        retval = PAM_AUTH_ERR;
        goto cleanup;
    }

    rc = oath_base32_decode(secret_base32, strlen(secret_base32),
                            &secret_binary, &secret_binary_length);
    ptsc_secure_memzero(secret_base32, sizeof(secret_base32));
    if (rc != OATH_OK) {
        retval = PAM_AUTH_ERR;
        goto cleanup;
    }

    now = time(NULL);
    if (now == (time_t)-1) {
        retval = PAM_AUTH_ERR;
        goto cleanup;
    }

    rc = oath_totp_validate3(secret_binary, secret_binary_length, now,
                             PTSC_TOTP_STEP, 0, PTSC_TOTP_WINDOW, NULL,
                             &counter, otp_input);
    if (rc >= 0 && fake_mode == 0) {
        int replay = totp_replay_check_and_store(slot->replay_tag, user_id,
                                                  counter);

        if (replay == TOTP_REPLAY_ACCEPTED) {
            retval = PAM_SUCCESS;
        } else {
            syslog(replay == TOTP_REPLAY_DETECTED ? LOG_NOTICE : LOG_ERR,
                   "pam_totp_slot_challenge: replay state rejected for user");
            retval = PAM_AUTH_ERR;
        }
    } else {
        retval = PAM_AUTH_ERR;
    }

cleanup:
    ptsc_secure_memzero(home, sizeof(home));
    ptsc_secure_memzero(secret_base32, sizeof(secret_base32));
    if (secret_binary != NULL) {
        ptsc_secure_memzero(secret_binary, secret_binary_length);
        free(secret_binary);
    }
    if (otp_input != NULL) {
        ptsc_secure_memzero(otp_input, otp_length);
        free(otp_input);
    }
    if (retval != PAM_SUCCESS) {
        pam_fail_delay(pamh, PTSC_FAIL_DELAY);
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
