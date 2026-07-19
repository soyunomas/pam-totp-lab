#define _GNU_SOURCE

#include "rollover.h"
#include "rollover_clock.h"
#include "scope.h"
#include "../pam_common/totp_replay.h"
#include "../pam_common/user_totp_secret.h"

#include <liboath/oath.h>
#include <pthread.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#define PTR_SECRET_FILE ".pam_totp_rollover"
#define PTR_FAKE_SECRET "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
#define PTR_FAIL_DELAY_US 3000000U
#define PTR_RESPONSE_SCAN_LIMIT 512U

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

static int parse_options(int argc, const char **argv, int *nullok_out)
{
    int nullok = 0;

    if (argc < 0 || nullok_out == NULL) return -1;
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

static void free_response(char **response, size_t length)
{
    if (response == NULL || *response == NULL) return;
    user_totp_secure_memzero(*response, length);
    free(*response);
    *response = NULL;
}

static int prompt_code(pam_handle_t *pamh, const char *prompt, char **response,
                       size_t *length_out)
{
    int result;

    if (pamh == NULL || prompt == NULL || response == NULL ||
        length_out == NULL) {
        return -1;
    }
    *response = NULL;
    *length_out = 0U;
    result = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, response, "%s", prompt);
    if (*response != NULL) {
        *length_out = strnlen(*response, PTR_RESPONSE_SCAN_LIMIT);
    }
    return result == PAM_SUCCESS &&
                   ptr_validate_otp_text(*response, *length_out) == 0
               ? 0
               : -1;
}

static int validate_exact_counter(const char *secret, size_t secret_length,
                                  time_t wall, const char *code,
                                  uint64_t expected_counter)
{
    uint64_t accepted_counter = UINT64_C(0);
    int result = oath_totp_validate3(
        secret, secret_length, wall, PTR_TOTP_STEP_SECONDS, 0, 0, NULL,
        &accepted_counter, code);

    return result >= 0 && accepted_counter == expected_counter ? 0 : -1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv)
{
    const char *username = NULL;
    const void *service_item = NULL;
    const char *service;
    char secret_base32[USER_TOTP_SECRET_MAX_LENGTH + 1U];
    char replay_tag[PTR_REPLAY_TAG_CAPACITY];
    char *secret_binary = NULL;
    size_t secret_binary_length = 0U;
    char *first_response = NULL;
    char *second_response = NULL;
    size_t first_length = 0U;
    size_t second_length = 0U;
    uid_t user_id = (uid_t)0;
    uint64_t first_counter = UINT64_C(0);
    uint64_t wall_counter = UINT64_C(0);
    struct timespec wall;
    struct timespec boundary;
    struct timespec deadline;
    struct timespec monotonic;
    struct totp_replay_transaction *transaction = NULL;
    int nullok = 0;
    int fake_mode = 0;
    int secret_hard_error = 0;
    int secret_status;
    int replay_status;
    int result = PAM_AUTH_ERR;

    (void)flags;
    memset(secret_base32, 0, sizeof(secret_base32));
    memset(replay_tag, 0, sizeof(replay_tag));
    memset(&wall, 0, sizeof(wall));
    memset(&boundary, 0, sizeof(boundary));
    memset(&deadline, 0, sizeof(deadline));
    memset(&monotonic, 0, sizeof(monotonic));

    if (pamh == NULL || parse_options(argc, argv, &nullok) != 0) {
        return PAM_SERVICE_ERR;
    }
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS ||
        username == NULL ||
        pam_get_item(pamh, PAM_SERVICE, &service_item) != PAM_SUCCESS ||
        service_item == NULL || ensure_oath() != 0) {
        result = PAM_SYSTEM_ERR;
        goto cleanup;
    }
    service = (const char *)service_item;
    if (ptr_validate_service(service) != 0) {
        result = PAM_SERVICE_ERR;
        goto cleanup;
    }

    secret_status = user_totp_secret_get(
        username, PTR_SECRET_FILE, secret_base32, sizeof(secret_base32),
        &user_id);
    if (secret_status != USER_TOTP_SECRET_OK) {
        if (secret_status == USER_TOTP_SECRET_NOT_FOUND && nullok) {
            result = PAM_IGNORE;
            goto cleanup;
        }
        fake_mode = 1;
        secret_hard_error = secret_status == USER_TOTP_SECRET_ERROR;
        memcpy(secret_base32, PTR_FAKE_SECRET, sizeof(PTR_FAKE_SECRET));
    }
    if (oath_base32_decode(secret_base32, strlen(secret_base32), &secret_binary,
                           &secret_binary_length) != OATH_OK) {
        result = PAM_SYSTEM_ERR;
        goto cleanup;
    }
    user_totp_secure_memzero(secret_base32, sizeof(secret_base32));
    if (ptr_make_replay_tag(service, (const unsigned char *)secret_binary,
                            secret_binary_length, replay_tag) != 0) {
        result = PAM_SYSTEM_ERR;
        goto cleanup;
    }

    if (prompt_code(pamh, "Primer código TOTP: ", &first_response,
                    &first_length) != 0) {
        syslog(LOG_NOTICE, "pam_totp_rollover: first conversation failed");
        result = PAM_AUTH_ERR;
        goto cleanup;
    }
    if (ptr_clock_wall_now(&wall) != 0 ||
        ptr_counter_from_wall(wall.tv_sec, &wall_counter) != 0 ||
        wall_counter == UINT64_MAX) {
        syslog(LOG_ERR, "pam_totp_rollover: first clock check failed");
        result = PAM_SYSTEM_ERR;
        goto cleanup;
    }
    if (validate_exact_counter(secret_binary, secret_binary_length, wall.tv_sec,
                               first_response, wall_counter) != 0 || fake_mode) {
        syslog(LOG_NOTICE, "pam_totp_rollover: first code rejected");
        result = secret_hard_error ? PAM_SYSTEM_ERR : PAM_AUTH_ERR;
        goto cleanup;
    }
    free_response(&first_response, first_length);
    first_length = 0U;
    first_counter = wall_counter;
    replay_status = totp_replay_transaction_begin(replay_tag, user_id,
                                                   &transaction);
    if (replay_status == TOTP_REPLAY_BUSY) {
        syslog(LOG_NOTICE, "pam_totp_rollover: authentication already active");
        result = PAM_AUTH_ERR;
        goto cleanup;
    }
    if (replay_status != TOTP_REPLAY_ACCEPTED) {
        syslog(LOG_ERR, "pam_totp_rollover: replay state unavailable");
        result = PAM_SYSTEM_ERR;
        goto cleanup;
    }
    if (ptr_clock_wall_now(&wall) != 0 ||
        ptr_counter_from_wall(wall.tv_sec, &wall_counter) != 0 ||
        wall_counter != first_counter) {
        syslog(LOG_NOTICE, "pam_totp_rollover: first period changed before consume");
        result = PAM_AUTH_ERR;
        goto cleanup;
    }
    replay_status = totp_replay_transaction_consume(transaction, first_counter);
    if (replay_status == TOTP_REPLAY_DETECTED) {
        syslog(LOG_NOTICE, "pam_totp_rollover: first code was already consumed");
        result = PAM_AUTH_ERR;
        goto cleanup;
    }
    if (replay_status != TOTP_REPLAY_ACCEPTED) {
        syslog(LOG_ERR, "pam_totp_rollover: first replay update failed");
        result = PAM_SYSTEM_ERR;
        goto cleanup;
    }
    if (ptr_clock_wall_now(&wall) != 0 ||
        ptr_clock_monotonic_now(&monotonic) != 0 ||
        ptr_plan_second_step(&wall, &monotonic, first_counter, &boundary,
                             &deadline) != 0 ||
        ptr_clock_wait_until(&boundary) != 0 ||
        ptr_clock_wall_now(&wall) != 0 ||
        ptr_clock_monotonic_now(&monotonic) != 0 ||
        !ptr_second_step_is_timely(wall.tv_sec, &monotonic, first_counter,
                                   &deadline)) {
        syslog(LOG_NOTICE, "pam_totp_rollover: second period was not reached safely");
        result = PAM_AUTH_ERR;
        goto cleanup;
    }

    if (prompt_code(pamh, "Código TOTP del periodo siguiente: ",
                    &second_response, &second_length) != 0) {
        syslog(LOG_NOTICE, "pam_totp_rollover: second conversation failed");
        result = PAM_AUTH_ERR;
        goto cleanup;
    }
    if (ptr_clock_wall_now(&wall) != 0 ||
        ptr_clock_monotonic_now(&monotonic) != 0 ||
        !ptr_second_step_is_timely(wall.tv_sec, &monotonic, first_counter,
                                   &deadline)) {
        syslog(LOG_NOTICE, "pam_totp_rollover: second response missed its deadline");
        result = PAM_AUTH_ERR;
        goto cleanup;
    }
    if (validate_exact_counter(secret_binary, secret_binary_length, wall.tv_sec,
                               second_response,
                               first_counter + UINT64_C(1)) != 0) {
        syslog(LOG_NOTICE, "pam_totp_rollover: second code rejected");
        result = PAM_AUTH_ERR;
        goto cleanup;
    }
    free_response(&second_response, second_length);
    second_length = 0U;

    replay_status = totp_replay_transaction_consume(
        transaction, first_counter + UINT64_C(1));
    if (replay_status != TOTP_REPLAY_ACCEPTED) {
        syslog(LOG_ERR, "pam_totp_rollover: second replay update failed");
        result = replay_status == TOTP_REPLAY_DETECTED ? PAM_AUTH_ERR
                                                       : PAM_SYSTEM_ERR;
        goto cleanup;
    }
    result = PAM_SUCCESS;

cleanup:
    totp_replay_transaction_end(&transaction);
    free_response(&first_response, first_length);
    free_response(&second_response, second_length);
    user_totp_secure_memzero(secret_base32, sizeof(secret_base32));
    user_totp_secure_memzero(replay_tag, sizeof(replay_tag));
    if (secret_binary != NULL) {
        user_totp_secure_memzero(secret_binary, secret_binary_length);
        free(secret_binary);
    }
    if (result != PAM_SUCCESS && result != PAM_IGNORE) {
        pam_fail_delay(pamh, PTR_FAIL_DELAY_US);
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
