#define _GNU_SOURCE

#include "challenge.h"
#include "secure_store.h"
#include "../pam_schedule_totp_override/rate_limit.h"

#include <openssl/crypto.h>
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

#define SPK_FAIL_DELAY 3000000U
#define SPK_MARKER_LIFETIME 120U
#define SPK_MARKER_KEY "pam_schedule_partial_key_override.authorization"

struct spk_authorization {
    uid_t uid;
    uint64_t service_hash;
    uint64_t authorizer_hash;
    uint64_t expires;
};

static uint64_t hash_text(const char *text)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    for (size_t i = 0U; text[i] != '\0'; i++) {
        hash ^= (uint64_t)(unsigned char)text[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static int rate_scope(char out[32], const char *service,
                      const char *authorizer)
{
    uint64_t hash;
    int written;
    if (out == NULL || service == NULL || authorizer == NULL) return -1;
    hash = hash_text(service);
    for (size_t i = 0U; authorizer[i] != '\0'; i++) {
        hash ^= (uint64_t)(unsigned char)authorizer[i];
        hash *= UINT64_C(1099511628211);
    }
    written = snprintf(out, 32U, "spk-%016llx",
                       (unsigned long long)hash);
    return written == 20 ? 0 : -1;
}

static int resolve_uid(const char *username, uid_t *uid_out)
{
    long configured = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t size = configured > 0 ? (size_t)configured : 16384U;
    struct passwd pwd;
    struct passwd *result = NULL;
    char *buffer;
    int status = -1;

    if (username == NULL || uid_out == NULL || size > 1048576U) return -1;
    buffer = calloc(1U, size);
    if (buffer == NULL) return -1;
    if (getpwnam_r(username, &pwd, buffer, size, &result) == 0 &&
        result != NULL) {
        *uid_out = pwd.pw_uid;
        status = 0;
    }
    pso_secure_memzero(buffer, size);
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
    *service_out = item;
    return 0;
}

static int local_time_now(struct tm *out)
{
    time_t now;
    if (out == NULL || unsetenv("TZ") != 0) return -1;
    tzset();
    now = time(NULL);
    return now == (time_t)-1 || localtime_r(&now, out) == NULL ? -1 : 0;
}

static int load_policy(const char *username, struct pso_config *config,
                       struct tm *local, const struct pso_rule **rule)
{
    if (spk_load_config(config) != SPK_STORE_OK || local_time_now(local) != 0) {
        return PSO_SCHEDULE_ERROR;
    }
    return pso_evaluate_schedule(config, username, local, rule);
}

static void marker_cleanup(pam_handle_t *pamh, void *data, int status)
{
    (void)pamh;
    (void)status;
    if (data != NULL) {
        pso_secure_memzero(data, sizeof(struct spk_authorization));
        free(data);
    }
}

static int remember(pam_handle_t *pamh, uid_t uid, const char *service,
                    const char *authorizer, uint64_t now)
{
    struct spk_authorization *marker;
    if (UINT64_MAX - now < SPK_MARKER_LIFETIME) return -1;
    marker = calloc(1U, sizeof(*marker));
    if (marker == NULL) return -1;
    marker->uid = uid;
    marker->service_hash = hash_text(service);
    marker->authorizer_hash = hash_text(authorizer);
    marker->expires = now + SPK_MARKER_LIFETIME;
    if (pam_set_data(pamh, SPK_MARKER_KEY, marker, marker_cleanup) !=
        PAM_SUCCESS) {
        marker_cleanup(pamh, marker, PAM_SYSTEM_ERR);
        return -1;
    }
    return 0;
}

static int marker_valid(pam_handle_t *pamh, uid_t uid, const char *service,
                        const char *authorizer, uint64_t now)
{
    const void *data = NULL;
    const struct spk_authorization *marker;
    if (pam_get_data(pamh, SPK_MARKER_KEY, &data) != PAM_SUCCESS ||
        data == NULL) {
        return 0;
    }
    marker = data;
    return marker->uid == uid && marker->service_hash == hash_text(service) &&
                   marker->authorizer_hash == hash_text(authorizer) &&
                   now <= marker->expires
               ? 1
               : 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv)
{
    const char *username = NULL;
    const char *service = NULL;
    const struct pso_rule *rule = NULL;
    struct pso_config config;
    struct pk_key_data key;
    struct tm local;
    unsigned char key_id[32];
    unsigned char computed[PK_HASH_LEN];
    size_t positions[SPK_CHALLENGE_COUNT] = {0U};
    char prompt[160];
    char rate_name[32];
    char *response = NULL;
    size_t response_length = 0U;
    uid_t uid = (uid_t)0;
    uint64_t monotonic = 0U;
    unsigned int mismatch = 0U;
    int schedule;
    int rc;
    int result = PAM_AUTH_ERR;

    (void)flags;
    (void)argv;
    memset(&config, 0, sizeof(config));
    pk_key_data_clear(&key);
    memset(&local, 0, sizeof(local));
    memset(key_id, 0, sizeof(key_id));
    memset(computed, 0, sizeof(computed));
    memset(prompt, 0, sizeof(prompt));
    memset(rate_name, 0, sizeof(rate_name));

    if (argc != 0) return PAM_SERVICE_ERR;
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS ||
        username == NULL || get_service(pamh, &service) != 0) {
        goto cleanup;
    }
    schedule = load_policy(username, &config, &local, &rule);
    if (schedule == PSO_SCHEDULE_UNMANAGED_IGNORE) {
        result = PAM_IGNORE;
        goto cleanup;
    }
    if (schedule == PSO_SCHEDULE_INSIDE) {
        result = PAM_SUCCESS;
        goto cleanup;
    }
    if (schedule != PSO_SCHEDULE_OUTSIDE || rule == NULL ||
        resolve_uid(username, &uid) != 0 ||
        pso_monotonic_seconds(&monotonic) != 0 ||
        rate_scope(rate_name, service, rule->secret_name) != 0) {
        goto cleanup;
    }
    rc = pso_rate_check(uid, rate_name, monotonic);
    if (rc != PSO_RATE_ALLOWED) {
        syslog(rc == PSO_RATE_BLOCKED ? LOG_NOTICE : LOG_ERR,
               "pam_schedule_partial_key_override: rate state rejected user=%s service=%s",
               username, service);
        goto cleanup;
    }
    if (spk_load_key(rule->secret_name, &key, key_id) != SPK_STORE_OK ||
        spk_reserve_challenge(uid, username, service, rule->secret_name, key_id,
                              key.pass_len, positions) != SPK_CHALLENGE_OK) {
        goto record_failure;
    }
    rc = snprintf(prompt, sizeof(prompt),
                  "Acceso fuera de horario. Clave docente, posiciones [%zu] [%zu] [%zu]: ",
                  positions[0] + 1U, positions[1] + 1U, positions[2] + 1U);
    if (rc < 0 || (size_t)rc >= sizeof(prompt) ||
        pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &response, "%s", prompt) !=
            PAM_SUCCESS ||
        response == NULL) {
        goto record_failure;
    }
    response_length = strnlen(response, PAM_MAX_RESP_SIZE);
    if (response_length != SPK_CHALLENGE_COUNT) goto record_failure;
    for (size_t i = 0U; i < SPK_CHALLENGE_COUNT; i++) {
        if (pk_hash_position(computed, key.salt, (int)positions[i],
                             response[i]) != 0) {
            goto record_failure;
        }
        mismatch |= (unsigned int)CRYPTO_memcmp(
            computed, key.hashes[positions[i]], PK_HASH_LEN);
        pso_secure_memzero(computed, sizeof(computed));
    }
    if (mismatch != 0U ||
        pso_rate_reset(uid, rate_name) != PSO_RATE_ALLOWED ||
        remember(pamh, uid, service, rule->secret_name, monotonic) != 0) {
        goto record_failure;
    }
    syslog(LOG_NOTICE,
           "pam_schedule_partial_key_override: teacher override accepted user=%s service=%s authorizer=%s",
           username, service, rule->secret_name);
    result = PAM_SUCCESS;
    goto cleanup;

record_failure:
    rc = pso_rate_record_failure(uid, rate_name, monotonic);
    syslog(rc == PSO_RATE_ERROR ? LOG_ERR : LOG_NOTICE,
           "pam_schedule_partial_key_override: teacher override rejected user=%s service=%s",
           username, service);

cleanup:
    if (response != NULL) {
        size_t wipe = response_length < PAM_MAX_RESP_SIZE
                          ? response_length + 1U
                          : PAM_MAX_RESP_SIZE;
        pso_secure_memzero(response, wipe);
        free(response);
    }
    pso_secure_memzero(&config, sizeof(config));
    pk_key_data_clear(&key);
    pso_secure_memzero(&local, sizeof(local));
    pso_secure_memzero(key_id, sizeof(key_id));
    pso_secure_memzero(computed, sizeof(computed));
    pso_secure_memzero(positions, sizeof(positions));
    pso_secure_memzero(prompt, sizeof(prompt));
    pso_secure_memzero(rate_name, sizeof(rate_name));
    if (result != PAM_SUCCESS && result != PAM_IGNORE) {
        (void)pam_fail_delay(pamh, SPK_FAIL_DELAY);
    }
    return result;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                                const char **argv)
{
    const char *username = NULL;
    const char *service = NULL;
    const struct pso_rule *rule = NULL;
    struct pso_config config;
    struct tm local;
    uid_t uid = (uid_t)0;
    uint64_t monotonic = 0U;
    int schedule;
    int result = PAM_PERM_DENIED;

    (void)flags;
    (void)argv;
    memset(&config, 0, sizeof(config));
    memset(&local, 0, sizeof(local));
    if (argc != 0) return PAM_SERVICE_ERR;
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS ||
        username == NULL || get_service(pamh, &service) != 0) {
        goto cleanup;
    }
    schedule = load_policy(username, &config, &local, &rule);
    if (schedule == PSO_SCHEDULE_UNMANAGED_IGNORE) {
        result = PAM_IGNORE;
    } else if (schedule == PSO_SCHEDULE_INSIDE) {
        result = PAM_SUCCESS;
    } else if (schedule == PSO_SCHEDULE_OUTSIDE && rule != NULL &&
               resolve_uid(username, &uid) == 0 &&
               pso_monotonic_seconds(&monotonic) == 0 &&
               marker_valid(pamh, uid, service, rule->secret_name,
                            monotonic) != 0) {
        result = PAM_SUCCESS;
    }

cleanup:
    pso_secure_memzero(&config, sizeof(config));
    pso_secure_memzero(&local, sizeof(local));
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
