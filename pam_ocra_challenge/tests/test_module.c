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

static char information[128];
static char prompt_text[64];
static unsigned int reserve_calls;
static unsigned int reset_calls;
static unsigned int fail_delay_calls;
static int prompt_result = PAM_SUCCESS;
static char *issued_response;
static size_t response_wipe_length;

int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt)
{
    struct passwd *entry;

    (void)pamh;
    (void)prompt;
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
    *value = "sudo";
    return PAM_SUCCESS;
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
    return PAM_SUCCESS;
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
    *response = strdup("75619513");
    issued_response = *response;
    return *response == NULL ? PAM_SYSTEM_ERR : prompt_result;
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
    assert(strcmp(service, "sudo") == 0);
    memcpy(record->secret, secret, OCRA_SECRET_BYTES);
    memcpy(record->key_id, "0011223344556677", OCRA_KEY_ID_HEX_LENGTH + 1U);
    return 0;
}

int ocra_rate_limit_reserve(uid_t uid, const char *service,
                            const char *key_id,
                            char challenge[OCRA_CHALLENGE_DIGITS + 1U])
{
    (void)uid;
    assert(strcmp(service, "sudo") == 0);
    assert(strcmp(key_id, "0011223344556677") == 0);
    memcpy(challenge, "1234567890", OCRA_CHALLENGE_DIGITS + 1U);
    reserve_calls++;
    return 0;
}

int ocra_rate_limit_reset(uid_t uid, const char *service, const char *key_id)
{
    (void)uid;
    assert(strcmp(service, "sudo") == 0);
    assert(strcmp(key_id, "0011223344556677") == 0);
    reset_calls++;
    return 0;
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

    prompt_result = PAM_SYSTEM_ERR;
    issued_response = NULL;
    response_wipe_length = 0U;
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR);
    assert(response_wipe_length == OCRA_RESPONSE_DIGITS);
    assert(fail_delay_calls == 1U);
}

int main(void)
{
    test_correct_response_authenticates();
    test_conversation_error_clears_allocated_response();
    puts("OCRA PAM module tests passed");
    return EXIT_SUCCESS;
}
