#define _GNU_SOURCE
#include "../schedule.h"
#include "../secure_store.h"
#include "../rate_limit.h"
#include "../../pam_common/totp_replay.h"
#include <liboath/oath.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct pam_handle {
    const char *user;
    const char *service;
    const char *answer;
    void *data;
    void (*cleanup)(pam_handle_t *, void *, int);
};

static int failures;
static int schedule_mode;
static int config_status;
static int secret_status;
static int rate_check_status;
static int replay_status;
static int oath_validate_status;
static uint64_t monotonic_value;
static int prompt_count;
static int failure_record_count;
static int reset_count;
static int delay_count;
static struct pso_rule test_rule;

static void check(int condition, const char *name)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

static void reset_state(void)
{
    schedule_mode = PSO_SCHEDULE_INSIDE;
    config_status = PSO_STORE_OK;
    secret_status = PSO_STORE_OK;
    rate_check_status = PSO_RATE_ALLOWED;
    replay_status = TOTP_REPLAY_ACCEPTED;
    oath_validate_status = 0;
    monotonic_value = 1000U;
    prompt_count = 0;
    failure_record_count = 0;
    reset_count = 0;
    delay_count = 0;
    memset(&test_rule, 0, sizeof(test_rule));
    strcpy(test_rule.user, "managed");
    strcpy(test_rule.secret_name, "managed.secret");
}

void pso_secure_memzero(void *buffer, size_t length)
{
    if (buffer != NULL) memset(buffer, 0, length);
}

int pso_validate_service(const char *service)
{
    return service != NULL && strchr(service, '/') == NULL ? 0 : -1;
}

int pso_load_config(struct pso_config *config_out)
{
    memset(config_out, 0, sizeof(*config_out));
    return config_status;
}

int pso_load_secret(const char *name, char *out, size_t capacity)
{
    (void)name;
    if (secret_status == PSO_STORE_OK) {
        const char value[] = "JBSWY3DPEHPK3PXP";
        if (sizeof(value) > capacity) return PSO_STORE_ERROR;
        memcpy(out, value, sizeof(value));
    }
    return secret_status;
}

int pso_evaluate_schedule(const struct pso_config *config, const char *username,
                          const struct tm *local_time,
                          const struct pso_rule **rule_out)
{
    (void)config;
    (void)username;
    (void)local_time;
    if (rule_out != NULL) {
        *rule_out = schedule_mode == PSO_SCHEDULE_OUTSIDE ? &test_rule : NULL;
    }
    return schedule_mode;
}

int pso_monotonic_seconds(uint64_t *out)
{
    *out = monotonic_value;
    return 0;
}

int pso_rate_check(uid_t uid, const char *service, uint64_t now)
{
    (void)uid;
    (void)service;
    (void)now;
    return rate_check_status;
}

int pso_rate_record_failure(uid_t uid, const char *service, uint64_t now)
{
    (void)uid;
    (void)service;
    (void)now;
    failure_record_count++;
    return PSO_RATE_ALLOWED;
}

int pso_rate_reset(uid_t uid, const char *service)
{
    (void)uid;
    (void)service;
    reset_count++;
    return PSO_RATE_ALLOWED;
}

int totp_replay_check_and_store(const char *tag, uid_t uid, uint64_t counter)
{
    (void)tag;
    (void)uid;
    (void)counter;
    return replay_status;
}

int oath_init(void) { return OATH_OK; }

int oath_base32_decode(const char *input, size_t length, char **out,
                       size_t *out_length)
{
    (void)input;
    (void)length;
    *out = malloc(4U);
    if (*out == NULL) return OATH_CRYPTO_ERROR;
    memcpy(*out, "key", 4U);
    *out_length = 3U;
    return OATH_OK;
}

int oath_totp_validate3(const char *secret, size_t secret_length, time_t now,
                        unsigned int step, time_t start, unsigned int window,
                        unsigned int *position, uint64_t *counter,
                        const char *otp)
{
    (void)secret;
    (void)secret_length;
    (void)now;
    (void)step;
    (void)start;
    (void)window;
    (void)position;
    (void)otp;
    *counter = 42U;
    return oath_validate_status;
}

int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt)
{
    (void)prompt;
    *user = pamh->user;
    return PAM_SUCCESS;
}

int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item)
{
    if (item_type != PAM_SERVICE) return PAM_SYSTEM_ERR;
    *item = pamh->service;
    return PAM_SUCCESS;
}

int pam_prompt(pam_handle_t *pamh, int style, char **response,
               const char *format, ...)
{
    (void)style;
    (void)format;
    prompt_count++;
    *response = pamh->answer == NULL ? NULL : strdup(pamh->answer);
    return *response == NULL ? PAM_CONV_ERR : PAM_SUCCESS;
}

int pam_fail_delay(pam_handle_t *pamh, unsigned int delay)
{
    (void)pamh;
    (void)delay;
    delay_count++;
    return PAM_SUCCESS;
}

int pam_set_data(pam_handle_t *pamh, const char *name, void *data,
                 void (*cleanup)(pam_handle_t *, void *, int))
{
    (void)name;
    if (pamh->data != NULL && pamh->cleanup != NULL) {
        pamh->cleanup(pamh, pamh->data, PAM_SUCCESS);
    }
    pamh->data = data;
    pamh->cleanup = cleanup;
    return PAM_SUCCESS;
}

int pam_get_data(const pam_handle_t *pamh, const char *name, const void **data)
{
    (void)name;
    *data = pamh->data;
    return pamh->data == NULL ? PAM_SYSTEM_ERR : PAM_SUCCESS;
}

extern int pam_sm_authenticate(pam_handle_t *, int, int, const char **);
extern int pam_sm_acct_mgmt(pam_handle_t *, int, int, const char **);

static void release_handle(struct pam_handle *handle)
{
    if (handle->data != NULL && handle->cleanup != NULL) {
        handle->cleanup(handle, handle->data, PAM_SUCCESS);
        handle->data = NULL;
    }
}

int main(void)
{
    struct passwd *pwd = getpwuid(geteuid());
    struct pam_handle handle;
    const char *unknown[] = {"unexpected"};

    if (pwd == NULL) return EXIT_FAILURE;
    memset(&handle, 0, sizeof(handle));
    handle.user = pwd->pw_name;
    handle.service = "login";
    handle.answer = "123456";

    reset_state();
    check(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_SUCCESS &&
              prompt_count == 0,
          "inside schedule needs no teacher code");

    reset_state();
    schedule_mode = PSO_SCHEDULE_OUTSIDE;
    check(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_SUCCESS &&
              prompt_count == 1 && reset_count == 1 &&
              failure_record_count == 0,
          "outside schedule accepts valid override");
    check(pam_sm_acct_mgmt(&handle, 0, 0, NULL) == PAM_SUCCESS,
          "account phase accepts fresh override marker");
    monotonic_value += 121U;
    check(pam_sm_acct_mgmt(&handle, 0, 0, NULL) == PAM_PERM_DENIED,
          "expired override marker denied");
    release_handle(&handle);

    reset_state();
    schedule_mode = PSO_SCHEDULE_OUTSIDE;
    handle.answer = "12345";
    check(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR &&
              failure_record_count == 1 && delay_count == 1,
          "malformed OTP records failure");
    handle.answer = "123456";

    reset_state();
    schedule_mode = PSO_SCHEDULE_OUTSIDE;
    rate_check_status = PSO_RATE_BLOCKED;
    check(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR &&
              prompt_count == 0,
          "blocked user is rejected before prompt");

    reset_state();
    schedule_mode = PSO_SCHEDULE_UNMANAGED_IGNORE;
    check(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_IGNORE &&
              pam_sm_acct_mgmt(&handle, 0, 0, NULL) == PAM_IGNORE,
          "unmanaged ignore is consistent");

    reset_state();
    schedule_mode = PSO_SCHEDULE_UNMANAGED_DENY;
    check(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR,
          "unmanaged deny is fail closed");

    reset_state();
    schedule_mode = PSO_SCHEDULE_OUTSIDE;
    secret_status = PSO_STORE_ERROR;
    check(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR &&
              prompt_count == 1 && failure_record_count == 1,
          "missing or unsafe secret cannot authenticate");

    reset_state();
    schedule_mode = PSO_SCHEDULE_OUTSIDE;
    replay_status = TOTP_REPLAY_DETECTED;
    check(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR &&
              failure_record_count == 1,
          "replayed TOTP rejected");

    reset_state();
    schedule_mode = PSO_SCHEDULE_OUTSIDE;
    check(pam_sm_acct_mgmt(&handle, 0, 0, NULL) == PAM_PERM_DENIED,
          "account phase denies missing override marker");

    reset_state();
    config_status = PSO_STORE_ERROR;
    check(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR,
          "unsafe configuration fails closed");

    reset_state();
    check(pam_sm_authenticate(&handle, 0, 1, unknown) == PAM_SERVICE_ERR,
          "unknown module option rejected");

    release_handle(&handle);
    if (failures != 0) return EXIT_FAILURE;
    puts("PAM module integration tests passed");
    return EXIT_SUCCESS;
}
