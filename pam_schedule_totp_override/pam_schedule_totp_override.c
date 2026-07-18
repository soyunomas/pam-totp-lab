#define _GNU_SOURCE

#include "rate_limit.h"
#include "schedule.h"
#include "secure_store.h"
#include "../pam_common/totp_replay.h"

#include <liboath/oath.h>
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

#define PSO_TOTP_STEP 30U
#define PSO_TOTP_WINDOW 1U
#define PSO_OTP_DIGITS 6U
#define PSO_FAIL_DELAY 3000000U
#define PSO_OVERRIDE_LIFETIME 120U
#define PSO_FAKE_SECRET "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
#define PSO_MARKER_KEY "pam_schedule_totp_override.authorization"

struct pso_authorization {
    uid_t user_id;
    uint64_t service_hash;
    uint64_t expires_monotonic;
};

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

static uint64_t fnv1a_append(uint64_t hash, const char *text)
{
    for (size_t i = 0U; text[i] != '\0'; i++) {
        hash ^= (uint64_t)(unsigned char)text[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint64_t service_hash(const char *service)
{
    return fnv1a_append(UINT64_C(1469598103934665603), service);
}

static int replay_tag(char *out, size_t capacity, const char *service,
                      const char *secret_name)
{
    uint64_t hash = service_hash(service);
    int written;

    hash = fnv1a_append(hash, ":");
    hash = fnv1a_append(hash, secret_name);
    written = snprintf(out, capacity, "pso_%016llx",
                       (unsigned long long)hash);
    return written >= 0 && (size_t)written < capacity ? 0 : -1;
}

static int resolve_user_id(const char *username, uid_t *uid_out)
{
    long configured_size;
    size_t buffer_size;
    char *buffer = NULL;
    struct passwd pwd;
    struct passwd *result = NULL;
    int status = -1;

    if (username == NULL || uid_out == NULL) return -1;
    configured_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    buffer_size = configured_size > 0 ? (size_t)configured_size : 16384U;
    if (buffer_size > (size_t)1048576U) return -1;

    buffer = calloc(1U, buffer_size);
    if (buffer == NULL) return -1;
    if (getpwnam_r(username, &pwd, buffer, buffer_size, &result) == 0 &&
        result != NULL) {
        *uid_out = pwd.pw_uid;
        status = 0;
    }
    pso_secure_memzero(buffer, buffer_size);
    free(buffer);
    return status;
}

static int get_service(pam_handle_t *pamh, const char **service_out)
{
    const void *item = NULL;

    if (pamh == NULL || service_out == NULL ||
        pam_get_item(pamh, PAM_SERVICE, &item) != PAM_SUCCESS || item == NULL ||
        pso_validate_service((const char *)item) != 0) {
        return -1;
    }
    *service_out = (const char *)item;
    return 0;
}

static int current_local_time(time_t *epoch_out, struct tm *local_out)
{
    time_t now;

    if (epoch_out == NULL || local_out == NULL) return -1;
    if (unsetenv("TZ") != 0) return -1;
    tzset();
    now = time(NULL);
    if (now == (time_t)-1 || localtime_r(&now, local_out) == NULL) return -1;
    *epoch_out = now;
    return 0;
}

static int validate_otp(const char *otp, size_t length)
{
    if (otp == NULL || length != PSO_OTP_DIGITS) return -1;
    for (size_t i = 0U; i < length; i++) {
        if (otp[i] < '0' || otp[i] > '9') return -1;
    }
    return 0;
}

static void authorization_cleanup(pam_handle_t *pamh, void *data,
                                  int error_status)
{
    (void)pamh;
    (void)error_status;
    if (data != NULL) {
        pso_secure_memzero(data, sizeof(struct pso_authorization));
        free(data);
    }
}

static int remember_override(pam_handle_t *pamh, uid_t user_id,
                             const char *service, uint64_t monotonic_now)
{
    struct pso_authorization *authorization;

    if (UINT64_MAX - monotonic_now < PSO_OVERRIDE_LIFETIME) return -1;
    authorization = calloc(1U, sizeof(*authorization));
    if (authorization == NULL) return -1;
    authorization->user_id = user_id;
    authorization->service_hash = service_hash(service);
    authorization->expires_monotonic = monotonic_now + PSO_OVERRIDE_LIFETIME;
    if (pam_set_data(pamh, PSO_MARKER_KEY, authorization,
                     authorization_cleanup) != PAM_SUCCESS) {
        authorization_cleanup(pamh, authorization, PAM_SYSTEM_ERR);
        return -1;
    }
    return 0;
}

static int override_is_valid(pam_handle_t *pamh, uid_t user_id,
                             const char *service, uint64_t monotonic_now)
{
    const void *data = NULL;
    const struct pso_authorization *authorization;

    if (pam_get_data(pamh, PSO_MARKER_KEY, &data) != PAM_SUCCESS || data == NULL) {
        return 0;
    }
    authorization = (const struct pso_authorization *)data;
    return authorization->user_id == user_id &&
                   authorization->service_hash == service_hash(service) &&
                   monotonic_now <= authorization->expires_monotonic
               ? 1
               : 0;
}

static int load_policy_for_user(const char *username, struct pso_config *config,
                                struct tm *local_time,
                                const struct pso_rule **rule_out)
{
    time_t ignored_epoch;

    if (pso_load_config(config) != PSO_STORE_OK ||
        current_local_time(&ignored_epoch, local_time) != 0) {
        return PSO_SCHEDULE_ERROR;
    }
    return pso_evaluate_schedule(config, username, local_time, rule_out);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv)
{
    const char *username = NULL;
    const char *service = NULL;
    const struct pso_rule *rule = NULL;
    struct pso_config config;
    struct tm local_time;
    uid_t user_id = (uid_t)0;
    uint64_t monotonic_now = 0U;
    char secret_base32[PSO_MAX_SECRET_LEN + 1U];
    char replay[32];
    char *secret_binary = NULL;
    size_t secret_binary_length = 0U;
    char *otp_input = NULL;
    size_t otp_length = 0U;
    uint64_t counter = 0U;
    int fake_mode = 0;
    int schedule_result;
    int retval = PAM_AUTH_ERR;
    int rc;
    time_t epoch_now;

    (void)flags;
    (void)argv;
    memset(&config, 0, sizeof(config));
    memset(&local_time, 0, sizeof(local_time));
    memset(secret_base32, 0, sizeof(secret_base32));
    memset(replay, 0, sizeof(replay));

    if (argc != 0) return PAM_SERVICE_ERR;
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || username == NULL ||
        get_service(pamh, &service) != 0 || ensure_oath() != 0) {
        goto cleanup;
    }

    schedule_result = load_policy_for_user(username, &config, &local_time, &rule);
    if (schedule_result == PSO_SCHEDULE_UNMANAGED_IGNORE) {
        retval = PAM_IGNORE;
        goto cleanup;
    }
    if (schedule_result == PSO_SCHEDULE_INSIDE) {
        retval = PAM_SUCCESS;
        goto cleanup;
    }
    if (schedule_result != PSO_SCHEDULE_OUTSIDE || rule == NULL ||
        resolve_user_id(username, &user_id) != 0 ||
        pso_monotonic_seconds(&monotonic_now) != 0) {
        goto cleanup;
    }

    rc = pso_rate_check(user_id, service, monotonic_now);
    if (rc != PSO_RATE_ALLOWED) {
        syslog(rc == PSO_RATE_BLOCKED ? LOG_NOTICE : LOG_ERR,
               "pam_schedule_totp_override: authorization rate state rejected user=%s service=%s",
               username, service);
        goto cleanup;
    }

    if (pso_load_secret(rule->secret_name, secret_base32,
                        sizeof(secret_base32)) != PSO_STORE_OK) {
        fake_mode = 1;
        memcpy(secret_base32, PSO_FAKE_SECRET, sizeof(PSO_FAKE_SECRET));
    }

    rc = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &otp_input,
                    "%s", "Acceso fuera de horario. Código de autorización docente: ");
    if (otp_input != NULL) otp_length = strnlen(otp_input, PAM_MAX_RESP_SIZE);
    if (rc != PAM_SUCCESS || validate_otp(otp_input, otp_length) != 0) {
        goto record_failure;
    }

    rc = oath_base32_decode(secret_base32, strlen(secret_base32),
                            &secret_binary, &secret_binary_length);
    pso_secure_memzero(secret_base32, sizeof(secret_base32));
    if (rc != OATH_OK || current_local_time(&epoch_now, &local_time) != 0) {
        goto record_failure;
    }

    rc = oath_totp_validate3(secret_binary, secret_binary_length, epoch_now,
                             PSO_TOTP_STEP, 0, PSO_TOTP_WINDOW, NULL, &counter,
                             otp_input);
    if (rc < 0 || fake_mode != 0 ||
        replay_tag(replay, sizeof(replay), service, rule->secret_name) != 0 ||
        totp_replay_check_and_store(replay, user_id, counter) !=
            TOTP_REPLAY_ACCEPTED ||
        pso_rate_reset(user_id, service) != PSO_RATE_ALLOWED ||
        remember_override(pamh, user_id, service, monotonic_now) != 0) {
        goto record_failure;
    }

    syslog(LOG_NOTICE,
           "pam_schedule_totp_override: teacher override accepted user=%s service=%s",
           username, service);
    retval = PAM_SUCCESS;
    goto cleanup;

record_failure:
    rc = pso_rate_record_failure(user_id, service, monotonic_now);
    syslog(rc == PSO_RATE_ERROR ? LOG_ERR : LOG_NOTICE,
           "pam_schedule_totp_override: teacher override rejected user=%s service=%s",
           username, service);
    retval = PAM_AUTH_ERR;

cleanup:
    pso_secure_memzero(&config, sizeof(config));
    pso_secure_memzero(&local_time, sizeof(local_time));
    pso_secure_memzero(secret_base32, sizeof(secret_base32));
    pso_secure_memzero(replay, sizeof(replay));
    if (secret_binary != NULL) {
        pso_secure_memzero(secret_binary, secret_binary_length);
        free(secret_binary);
    }
    if (otp_input != NULL) {
        pso_secure_memzero(otp_input, otp_length);
        free(otp_input);
    }
    if (retval != PAM_SUCCESS && retval != PAM_IGNORE) {
        pam_fail_delay(pamh, PSO_FAIL_DELAY);
    }
    return retval;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                                const char **argv)
{
    const char *username = NULL;
    const char *service = NULL;
    const struct pso_rule *rule = NULL;
    struct pso_config config;
    struct tm local_time;
    uid_t user_id = (uid_t)0;
    uint64_t monotonic_now = 0U;
    int schedule_result;
    int retval = PAM_PERM_DENIED;

    (void)flags;
    (void)argv;
    memset(&config, 0, sizeof(config));
    memset(&local_time, 0, sizeof(local_time));

    if (argc != 0) return PAM_SERVICE_ERR;
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || username == NULL ||
        get_service(pamh, &service) != 0) {
        goto cleanup;
    }

    schedule_result = load_policy_for_user(username, &config, &local_time, &rule);
    if (schedule_result == PSO_SCHEDULE_UNMANAGED_IGNORE) {
        retval = PAM_IGNORE;
    } else if (schedule_result == PSO_SCHEDULE_INSIDE) {
        retval = PAM_SUCCESS;
    } else if (schedule_result == PSO_SCHEDULE_OUTSIDE && rule != NULL &&
               resolve_user_id(username, &user_id) == 0 &&
               pso_monotonic_seconds(&monotonic_now) == 0 &&
               override_is_valid(pamh, user_id, service, monotonic_now) != 0) {
        retval = PAM_SUCCESS;
    }

cleanup:
    pso_secure_memzero(&config, sizeof(config));
    pso_secure_memzero(&local_time, sizeof(local_time));
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
