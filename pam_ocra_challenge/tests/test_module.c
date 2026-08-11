#define _GNU_SOURCE

#include "../rate_limit.h"
#include "../secret_store.h"
#include "../secure_memory.h"

#include <assert.h>
#include <pwd.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct pam_handle {
    int unused;
};

__attribute__((weak)) int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                               int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_AUTH_ERR;
}

extern int pam_sm_setcred(pam_handle_t *, int, int, const char **);

static char information[128];
static char prompt_text[64];
static unsigned int reserve_calls;
static unsigned int reset_calls;
static unsigned int fail_delay_calls;
static unsigned int information_calls;
static unsigned int prompt_calls;
static unsigned int secret_load_calls;
static int user_result = PAM_SUCCESS;
static int item_result = PAM_SUCCESS;
static int information_result = PAM_SUCCESS;
static int prompt_result = PAM_SUCCESS;
static int secret_load_result;
static int reserve_result;
static int reset_result;
static int expect_fake_key;
static const char *username_override;
static const char *service_text = "sudo";
static const char *response_text = "75619513";
static const char *challenge_text = "1234567890";
static char *issued_response;
static size_t response_wipe_length;

static void reset_state(void)
{
    (void)memset(information, 0, sizeof(information));
    (void)memset(prompt_text, 0, sizeof(prompt_text));
    reserve_calls = 0U;
    reset_calls = 0U;
    fail_delay_calls = 0U;
    information_calls = 0U;
    prompt_calls = 0U;
    secret_load_calls = 0U;
    user_result = PAM_SUCCESS;
    item_result = PAM_SUCCESS;
    information_result = PAM_SUCCESS;
    prompt_result = PAM_SUCCESS;
    secret_load_result = 0;
    reserve_result = 0;
    reset_result = 0;
    expect_fake_key = 0;
    username_override = NULL;
    service_text = "sudo";
    response_text = "75619513";
    challenge_text = "1234567890";
    issued_response = NULL;
    response_wipe_length = 0U;
}

int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt)
{
    struct passwd *entry;

    (void)pamh;
    (void)prompt;
    if (user_result != PAM_SUCCESS) {
        return user_result;
    }
    if (username_override != NULL) {
        *user = username_override;
        return PAM_SUCCESS;
    }
    entry = getpwuid(getuid());
    if (entry == NULL) {
        return PAM_SYSTEM_ERR;
    }
    *user = entry->pw_name;
    return PAM_SUCCESS;
}

int pam_get_item(const pam_handle_t *pamh, int item, const void **value)
{
    (void)pamh;
    assert(item == PAM_SERVICE);
    if (item_result != PAM_SUCCESS) {
        return item_result;
    }
    *value = service_text;
    return item_result;
}

int pam_info(pam_handle_t *pamh, const char *format, ...)
{
    va_list arguments;
    const char *message;

    (void)pamh;
    assert(strcmp(format, "%s") == 0);
    va_start(arguments, format);
    message = va_arg(arguments, const char *);
    va_end(arguments);
    assert(snprintf(information, sizeof(information), "%s", message) > 0);
    information_calls++;
    return information_result;
}

int pam_prompt(pam_handle_t *pamh, int style, char **response,
               const char *format, ...)
{
    va_list arguments;
    const char *prompt;

    (void)pamh;
    assert(style == PAM_PROMPT_ECHO_OFF);
    assert(strcmp(format, "%s") == 0);
    va_start(arguments, format);
    prompt = va_arg(arguments, const char *);
    va_end(arguments);
    assert(snprintf(prompt_text, sizeof(prompt_text), "%s", prompt) > 0);
    prompt_calls++;
    *response = response_text == NULL ? NULL : strdup(response_text);
    issued_response = *response;
    return response_text != NULL && *response == NULL ? PAM_SYSTEM_ERR
                                                      : prompt_result;
}

int pam_fail_delay(pam_handle_t *pamh, unsigned int delay)
{
    (void)pamh;
    assert(delay == 3000000U);
    fail_delay_calls++;
    return PAM_SUCCESS;
}

int ocra_secret_store_load(uid_t uid, const char *service,
                           struct ocra_secret_record *record)
{
    static const unsigned char secret[] =
        "12345678901234567890123456789012";

    (void)uid;
    assert(strcmp(service, service_text) == 0);
    secret_load_calls++;
    if (secret_load_result == 0) {
        memcpy(record->secret, secret, OCRA_SECRET_BYTES);
        memcpy(record->key_id, "0011223344556677",
               OCRA_KEY_ID_HEX_LENGTH + 1U);
    }
    return secret_load_result;
}

int ocra_rate_limit_reserve(uid_t uid, const char *service,
                            const char *key_id,
    char challenge[OCRA_CHALLENGE_DIGITS + 1U])
{
    (void)uid;
    assert(strcmp(service, service_text) == 0);
    assert(strcmp(key_id, expect_fake_key != 0 ? "ffffffffffffffff"
                                               : "0011223344556677") == 0);
    reserve_calls++;
    if (reserve_result == 0) {
        memcpy(challenge, challenge_text, OCRA_CHALLENGE_DIGITS + 1U);
    }
    return reserve_result;
}

int ocra_rate_limit_reset(uid_t uid, const char *service, const char *key_id)
{
    (void)uid;
    assert(strcmp(service, service_text) == 0);
    assert(strcmp(key_id, "0011223344556677") == 0);
    reset_calls++;
    return reset_result;
}

void ocra_secret_record_clear(struct ocra_secret_record *record)
{
    if (record != NULL) {
        memset(record, 0, sizeof(*record));
    }
}

void secure_memory_clear(void *buffer, size_t length)
{
    volatile unsigned char *cursor = buffer;

    if (buffer == issued_response) {
        response_wipe_length = length;
    }
    if (buffer == NULL) {
        return;
    }
    while (length-- > 0U) {
        *cursor++ = 0U;
    }
}

static void test_correct_response_authenticates(void)
{
    struct pam_handle handle = {0};

    reset_state();
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_SUCCESS);
    assert(strcmp(information,
                  "Desafío OCRA para sudo: 1234567890") == 0);
    assert(strcmp(prompt_text, "Respuesta OCRA: ") == 0);
    assert(reserve_calls == 1U && reset_calls == 1U);
    assert(fail_delay_calls == 0U);
}

static void test_conversation_error_clears_allocated_response(void)
{
    struct pam_handle handle = {0};

    reset_state();
    prompt_result = PAM_SYSTEM_ERR;
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR);
    assert(response_wipe_length == OCRA_RESPONSE_DIGITS);
    assert(fail_delay_calls == 1U);
}

static void test_invalid_responses_fail_closed(void)
{
    static const char *const invalid[] = {
        "00000000", "7561951", "756195130", "75619X13", NULL,
    };
    struct pam_handle handle = {0};
    size_t index;

    for (index = 0U; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        reset_state();
        response_text = invalid[index];
        assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR);
        assert(reserve_calls == 1U && reset_calls == 0U);
        assert(information_calls == 1U && prompt_calls == 1U);
        assert(fail_delay_calls == 1U);
    }

    reset_state();
    challenge_text = "0000000001";
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR);
    assert(reset_calls == 0U && fail_delay_calls == 1U);
}

static void test_fake_routes_keep_the_external_contract(void)
{
    struct pam_handle handle = {0};

    reset_state();
    username_override = "ocra-user-that-does-not-exist";
    expect_fake_key = 1;
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR);
    assert(secret_load_calls == 0U && reserve_calls == 1U);
    assert(information_calls == 1U && prompt_calls == 1U);
    assert(strcmp(information,
                  "Desafío OCRA para sudo: 1234567890") == 0);
    assert(strcmp(prompt_text, "Respuesta OCRA: ") == 0);

    reset_state();
    secret_load_result = -1;
    expect_fake_key = 1;
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR);
    assert(secret_load_calls == 1U && reserve_calls == 1U);
    assert(information_calls == 1U && prompt_calls == 1U);
    assert(reset_calls == 0U && fail_delay_calls == 1U);
}

static void test_configuration_and_dependency_failures(void)
{
    struct pam_handle handle = {0};
    const char *unknown[] = {"nullok"};

    reset_state();
    assert(pam_sm_authenticate(&handle, 0, 1, unknown) == PAM_SERVICE_ERR);
    assert(reserve_calls == 0U && fail_delay_calls == 0U);

    reset_state();
    service_text = "invalid/service";
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_SERVICE_ERR);
    assert(secret_load_calls == 0U && reserve_calls == 0U);

    reset_state();
    reserve_result = -1;
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR);
    assert(reserve_calls == 1U && information_calls == 0U &&
           prompt_calls == 0U && fail_delay_calls == 1U);

    reset_state();
    information_result = PAM_SYSTEM_ERR;
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR);
    assert(information_calls == 1U && prompt_calls == 0U);

    reset_state();
    reset_result = -1;
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR);
    assert(reset_calls == 1U && fail_delay_calls == 1U);

    assert(pam_sm_setcred(&handle, 0, 0, NULL) == PAM_SUCCESS);
}

int main(void)
{
    test_correct_response_authenticates();
    test_conversation_error_clears_allocated_response();
    test_invalid_responses_fail_closed();
    test_fake_routes_keep_the_external_contract();
    test_configuration_and_dependency_failures();
    puts("OCRA PAM module tests passed");
    return EXIT_SUCCESS;
}
