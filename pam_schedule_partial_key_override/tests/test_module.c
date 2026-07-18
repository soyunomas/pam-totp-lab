#define _GNU_SOURCE

#include "../challenge.h"
#include "../secure_store.h"
#include "../../pam_schedule_totp_override/rate_limit.h"

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <pwd.h>
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
static int prompt_count;
static int failure_count;
static struct pso_rule rule;

static void check(int condition, const char *name)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

void pso_secure_memzero(void *buffer, size_t length)
{
    if (buffer != NULL) memset(buffer, 0, length);
}

int pso_validate_service(const char *service)
{
    return service != NULL && strchr(service, '/') == NULL ? 0 : -1;
}

int spk_load_config(struct pso_config *config)
{
    memset(config, 0, sizeof(*config));
    return SPK_STORE_OK;
}

int pso_evaluate_schedule(const struct pso_config *config, const char *username,
                          const struct tm *local, const struct pso_rule **out)
{
    (void)config;
    (void)username;
    (void)local;
    *out = schedule_mode == PSO_SCHEDULE_OUTSIDE ? &rule : NULL;
    return schedule_mode;
}

int pso_monotonic_seconds(uint64_t *out)
{
    *out = 1000U;
    return 0;
}

int pso_rate_check(uid_t uid, const char *service, uint64_t now)
{
    (void)uid;
    (void)service;
    (void)now;
    return PSO_RATE_ALLOWED;
}

int pso_rate_record_failure(uid_t uid, const char *service, uint64_t now)
{
    (void)uid;
    (void)service;
    (void)now;
    failure_count++;
    return PSO_RATE_ALLOWED;
}

int pso_rate_reset(uid_t uid, const char *service)
{
    (void)uid;
    (void)service;
    return PSO_RATE_ALLOWED;
}

int spk_load_key(const char *authorizer, struct pk_key_data *key,
                 unsigned char key_id[32])
{
    (void)authorizer;
    pk_key_data_clear(key);
    key->pass_len = 8U;
    key->hashes[0][0] = (unsigned char)'a';
    key->hashes[1][0] = (unsigned char)'b';
    key->hashes[2][0] = (unsigned char)'c';
    memset(key_id, 0x11, 32U);
    return SPK_STORE_OK;
}

int spk_reserve_challenge(uid_t uid, const char *username, const char *service,
                          const char *authorizer,
                          const unsigned char key_id[32], size_t pass_len,
                          size_t positions[3])
{
    (void)uid;
    (void)username;
    (void)service;
    (void)authorizer;
    (void)key_id;
    (void)pass_len;
    positions[0] = 0U;
    positions[1] = 1U;
    positions[2] = 2U;
    return SPK_CHALLENGE_OK;
}

int pk_hash_position(unsigned char output[PK_HASH_LEN],
                     const unsigned char salt[PK_SALT_LEN], int index,
                     char character)
{
    (void)salt;
    (void)index;
    memset(output, 0, PK_HASH_LEN);
    output[0] = (unsigned char)character;
    return 0;
}

void pk_key_data_clear(struct pk_key_data *data)
{
    memset(data, 0, sizeof(*data));
}

int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt)
{
    (void)prompt;
    *user = pamh->user;
    return PAM_SUCCESS;
}

int pam_get_item(const pam_handle_t *pamh, int type, const void **item)
{
    if (type != PAM_SERVICE) return PAM_SYSTEM_ERR;
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
    return PAM_SUCCESS;
}

int pam_set_data(pam_handle_t *pamh, const char *name, void *data,
                 void (*cleanup)(pam_handle_t *, void *, int))
{
    (void)name;
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

static void reset(struct pam_handle *handle)
{
    if (handle->data != NULL && handle->cleanup != NULL) {
        handle->cleanup(handle, handle->data, PAM_SUCCESS);
    }
    handle->data = NULL;
    handle->cleanup = NULL;
    prompt_count = 0;
    failure_count = 0;
}

int main(void)
{
    struct passwd *pwd = getpwuid(geteuid());
    struct pam_handle handle;
    const char *unknown[] = {"unknown"};
    if (pwd == NULL) return EXIT_FAILURE;
    memset(&handle, 0, sizeof(handle));
    memset(&rule, 0, sizeof(rule));
    strcpy(rule.secret_name, "profesor-1");
    handle.user = pwd->pw_name;
    handle.service = "sshd";
    handle.answer = "abc";

    schedule_mode = PSO_SCHEDULE_INSIDE;
    check(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_SUCCESS &&
              prompt_count == 0,
          "inside schedule has no teacher prompt");
    reset(&handle);

    schedule_mode = PSO_SCHEDULE_OUTSIDE;
    check(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_SUCCESS &&
              prompt_count == 1 &&
              pam_sm_acct_mgmt(&handle, 0, 0, NULL) == PAM_SUCCESS,
          "outside schedule accepts partial teacher key and account marker");
    reset(&handle);

    handle.answer = "bad";
    check(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR &&
              failure_count == 1,
          "wrong partial response is rejected and rate counted");
    reset(&handle);

    schedule_mode = PSO_SCHEDULE_UNMANAGED_IGNORE;
    check(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_IGNORE,
          "unmanaged ignore policy is preserved");
    reset(&handle);
    check(pam_sm_authenticate(&handle, 0, 1, unknown) == PAM_SERVICE_ERR,
          "module arguments are rejected");
    reset(&handle);

    if (failures == 0) puts("schedule partial-key PAM tests passed");
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
