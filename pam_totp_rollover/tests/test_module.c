#define _GNU_SOURCE

#include "../rollover.h"
#include "../../pam_common/totp_replay.h"
#include "../../pam_common/user_totp_secret.h"

#include <assert.h>
#include <liboath/oath.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct pam_handle {
    int unused;
};

extern int pam_sm_authenticate(pam_handle_t *, int, int, const char **);

static const char *responses[2];
static unsigned int prompt_calls;
static unsigned int fail_delay_calls;
static unsigned int oath_calls;
static unsigned int consume_calls;
static unsigned int transaction_end_calls;
static uint64_t consumed[2];
static int secret_status;
static int begin_status;
static int consume_statuses[2];
static int oath_fail_call;
static int prompt_fail_call;
static const char *service_name;
static struct timespec wall_values[5];
static size_t wall_count;
static size_t wall_index;
static struct timespec mono_values[3];
static size_t mono_count;
static size_t mono_index;
static struct timespec waited_boundary;
static int saw_long_wipe;

static void reset_state(void)
{
    responses[0] = "111111";
    responses[1] = "222222";
    prompt_calls = 0U;
    fail_delay_calls = 0U;
    oath_calls = 0U;
    consume_calls = 0U;
    transaction_end_calls = 0U;
    memset(consumed, 0, sizeof(consumed));
    secret_status = USER_TOTP_SECRET_OK;
    begin_status = TOTP_REPLAY_ACCEPTED;
    consume_statuses[0] = TOTP_REPLAY_ACCEPTED;
    consume_statuses[1] = TOTP_REPLAY_ACCEPTED;
    oath_fail_call = -1;
    prompt_fail_call = -1;
    service_name = "sshd";
    wall_values[0] = (struct timespec){.tv_sec = (time_t)60, .tv_nsec = 0L};
    wall_values[1] = (struct timespec){.tv_sec = (time_t)60, .tv_nsec = 0L};
    wall_values[2] = (struct timespec){.tv_sec = (time_t)60, .tv_nsec = 0L};
    wall_values[3] = (struct timespec){.tv_sec = (time_t)90, .tv_nsec = 0L};
    wall_values[4] = (struct timespec){.tv_sec = (time_t)90, .tv_nsec = 0L};
    wall_count = 5U;
    wall_index = 0U;
    mono_values[0] = (struct timespec){.tv_sec = (time_t)100, .tv_nsec = 0L};
    mono_values[1] = (struct timespec){.tv_sec = (time_t)130, .tv_nsec = 0L};
    mono_values[2] = (struct timespec){.tv_sec = (time_t)131, .tv_nsec = 0L};
    mono_count = 3U;
    mono_index = 0U;
    memset(&waited_boundary, 0, sizeof(waited_boundary));
    saw_long_wipe = 0;
}

int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt)
{
    (void)pamh;
    (void)prompt;
    *user = "testuser";
    return PAM_SUCCESS;
}

int pam_get_item(const pam_handle_t *pamh, int item, const void **value)
{
    (void)pamh;
    assert(item == PAM_SERVICE);
    *value = service_name;
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
    if (prompt_calls == 0U) {
        assert(strcmp(prompt, "Primer código TOTP: ") == 0);
    } else {
        assert(strcmp(prompt, "Código TOTP del periodo siguiente: ") == 0);
    }
    assert(prompt_calls < 2U);
    *response = strdup(responses[prompt_calls]);
    if (*response == NULL) return PAM_SYSTEM_ERR;
    return prompt_fail_call == (int)prompt_calls++ ? PAM_SYSTEM_ERR
                                                   : PAM_SUCCESS;
}

int pam_fail_delay(pam_handle_t *pamh, unsigned int delay)
{
    (void)pamh;
    assert(delay == 3000000U);
    fail_delay_calls++;
    return PAM_SUCCESS;
}

int oath_init(void)
{
    return OATH_OK;
}

int oath_base32_decode(const char *input, size_t input_length, char **output,
                       size_t *output_length)
{
    assert(input != NULL && input_length >= 16U);
    *output = malloc(4U);
    if (*output == NULL) return OATH_CRYPTO_ERROR;
    memcpy(*output, "seed", 4U);
    *output_length = 4U;
    return OATH_OK;
}

int oath_totp_validate3(const char *secret, size_t secret_length, time_t now,
                        unsigned int step, time_t start_offset, size_t window,
                        int *position, uint64_t *counter, const char *otp)
{
    unsigned int current_call = oath_calls++;

    (void)start_offset;
    (void)position;
    assert(secret != NULL && secret_length == 4U);
    assert(step == PTR_TOTP_STEP_SECONDS && window == 0U);
    assert(otp != NULL);
    *counter = (uint64_t)now / PTR_TOTP_STEP_SECONDS;
    return oath_fail_call == (int)current_call ? -1 : 0;
}

int user_totp_secret_get(const char *username, const char *filename,
                         char *secret_out, size_t secret_capacity,
                         uid_t *uid_out)
{
    const char value[] = "JBSWY3DPEHPK3PXP";

    assert(strcmp(username, "testuser") == 0);
    assert(strcmp(filename, ".pam_totp_rollover") == 0);
    assert(secret_capacity >= sizeof(value));
    *uid_out = (uid_t)1000;
    if (secret_status == USER_TOTP_SECRET_OK) {
        memcpy(secret_out, value, sizeof(value));
    }
    return secret_status;
}

void user_totp_secure_memzero(void *buffer, size_t length)
{
    volatile unsigned char *cursor = buffer;
    if (buffer == NULL) return;
    if (length == 100U) saw_long_wipe = 1;
    while (length-- > 0U) *cursor++ = 0U;
}

int totp_replay_transaction_begin(const char *tag, uid_t user_id,
                                  struct totp_replay_transaction **out)
{
    assert(tag != NULL && strncmp(tag, "ptr_", 4U) == 0);
    assert(user_id == (uid_t)1000);
    if (begin_status == TOTP_REPLAY_ACCEPTED) {
        *out = (struct totp_replay_transaction *)(uintptr_t)1U;
    }
    return begin_status;
}

int totp_replay_transaction_consume(struct totp_replay_transaction *transaction,
                                    uint64_t counter)
{
    assert(transaction != NULL);
    assert(consume_calls < 2U);
    consumed[consume_calls] = counter;
    return consume_statuses[consume_calls++];
}

void totp_replay_transaction_end(struct totp_replay_transaction **transaction)
{
    if (transaction != NULL && *transaction != NULL) {
        transaction_end_calls++;
        *transaction = NULL;
    }
}

int ptr_clock_wall_now(struct timespec *out)
{
    if (out == NULL || wall_index >= wall_count) return -1;
    *out = wall_values[wall_index++];
    return 0;
}

int ptr_clock_monotonic_now(struct timespec *out)
{
    if (out == NULL || mono_index >= mono_count) return -1;
    *out = mono_values[mono_index++];
    return 0;
}

int ptr_clock_wait_until(const struct timespec *deadline)
{
    assert(deadline != NULL);
    waited_boundary = *deadline;
    return 0;
}

static void test_success(void)
{
    struct pam_handle handle = {0};

    reset_state();
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_SUCCESS);
    assert(prompt_calls == 2U && oath_calls == 2U && consume_calls == 2U);
    assert(consumed[0] == UINT64_C(2) && consumed[1] == UINT64_C(3));
    assert(waited_boundary.tv_sec == (time_t)130);
    assert(fail_delay_calls == 0U);
    assert(transaction_end_calls == 1U);
}

static void test_failures(void)
{
    struct pam_handle handle = {0};
    const char *bad_option[] = {"window=1"};
    const char *nullok[] = {"nullok"};

    reset_state();
    assert(pam_sm_authenticate(&handle, 0, 1, bad_option) == PAM_SERVICE_ERR);

    reset_state();
    responses[0] = "12X456";
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR);
    assert(prompt_calls == 1U && oath_calls == 0U && consume_calls == 0U);
    assert(fail_delay_calls == 1U);

    reset_state();
    responses[0] =
        "11111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111";
    assert(strlen(responses[0]) == 100U);
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR);
    assert(saw_long_wipe == 1);

    reset_state();
    begin_status = TOTP_REPLAY_BUSY;
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR);
    assert(prompt_calls == 1U && oath_calls == 1U && fail_delay_calls == 1U);

    reset_state();
    oath_fail_call = 1;
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR);
    assert(prompt_calls == 2U && consume_calls == 1U);
    assert(transaction_end_calls == 1U);

    reset_state();
    prompt_fail_call = 1;
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR);
    assert(prompt_calls == 2U && consume_calls == 1U);
    assert(transaction_end_calls == 1U);

    reset_state();
    mono_values[2].tv_sec = (time_t)156;
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR);
    assert(prompt_calls == 2U && consume_calls == 1U && oath_calls == 1U);

    reset_state();
    consume_statuses[0] = TOTP_REPLAY_DETECTED;
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_AUTH_ERR);
    assert(consume_calls == 1U && prompt_calls == 1U);

    reset_state();
    consume_statuses[1] = TOTP_REPLAY_ERROR;
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_SYSTEM_ERR);
    assert(consume_calls == 2U && prompt_calls == 2U);

    reset_state();
    secret_status = USER_TOTP_SECRET_NOT_FOUND;
    assert(pam_sm_authenticate(&handle, 0, 1, nullok) == PAM_IGNORE);
    assert(prompt_calls == 0U && fail_delay_calls == 0U);

    reset_state();
    secret_status = USER_TOTP_SECRET_ERROR;
    assert(pam_sm_authenticate(&handle, 0, 0, NULL) == PAM_SYSTEM_ERR);
    assert(prompt_calls == 1U && consume_calls == 0U);
}

int main(void)
{
    test_success();
    test_failures();
    puts("rollover module integration tests passed");
    return EXIT_SUCCESS;
}
