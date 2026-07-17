#define _GNU_SOURCE

#include "../config.h"
#include "../secret.h"
#include "../slot_policy.h"
#include "../../pam_common/totp_replay.h"

#include <assert.h>
#include <liboath/oath.h>
#include <pwd.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

struct pam_handle {
    int unused;
};

extern int pam_sm_authenticate(pam_handle_t *, int, int, const char **);

static size_t selected_index;
static int secret_status = PTSC_SECRET_OK;
static int replay_status = TOTP_REPLAY_ACCEPTED;
static const char *response_text = "123456";
static char captured_prompt[128];
static char captured_replay_tag[64];
static unsigned int fail_delay_calls;
static unsigned int oath_validate_calls;

static const struct ptsc_slot test_slots[PTSC_MAX_SLOTS] = {
    {'A', "A.secret", "A", "pam_totp_slot_a"},
    {'B', "B.secret", "B", "pam_totp_slot_b"},
    {'C', "C.secret", "C", "pam_totp_slot_c"},
    {'D', "D.secret", "D", "pam_totp_slot_d"},
};

static void reset_state(void)
{
    selected_index = 0U;
    secret_status = PTSC_SECRET_OK;
    replay_status = TOTP_REPLAY_ACCEPTED;
    response_text = "123456";
    memset(captured_prompt, 0, sizeof(captured_prompt));
    memset(captured_replay_tag, 0, sizeof(captured_replay_tag));
    fail_delay_calls = 0U;
    oath_validate_calls = 0U;
}

int ptsc_validate_slot_count(size_t slot_count)
{
    return slot_count >= PTSC_MIN_SLOTS && slot_count <= PTSC_MAX_SLOTS ? 0 : -1;
}

const struct ptsc_slot *ptsc_slot_by_index(size_t index)
{
    return index < PTSC_MAX_SLOTS ? &test_slots[index] : NULL;
}

int ptsc_random_index(size_t slot_count, size_t *index_out)
{
    if (index_out == NULL || selected_index >= slot_count) {
        return -1;
    }
    *index_out = selected_index;
    return 0;
}

void ptsc_secure_memzero(void *buffer, size_t length)
{
    volatile unsigned char *cursor = buffer;

    if (buffer == NULL) {
        return;
    }
    while (length-- > 0U) {
        *cursor++ = 0U;
    }
}

int ptsc_read_slot_secret(const char *home_directory, uid_t expected_owner,
                          size_t slot_index, char *secret_out,
                          size_t secret_capacity)
{
    const char value[] = "JBSWY3DPEHPK3PXP";

    (void)home_directory;
    (void)expected_owner;
    if (slot_index != selected_index || secret_out == NULL ||
        secret_capacity < sizeof(value)) {
        return PTSC_SECRET_ERROR;
    }
    if (secret_status == PTSC_SECRET_OK) {
        memcpy(secret_out, value, sizeof(value));
    }
    return secret_status;
}

int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt)
{
    struct passwd *pwd;

    (void)pamh;
    (void)prompt;
    pwd = getpwuid(getuid());
    if (pwd == NULL) {
        return PAM_AUTH_ERR;
    }
    *user = pwd->pw_name;
    return PAM_SUCCESS;
}

int pam_prompt(pam_handle_t *pamh, int style, char **response,
               const char *format, ...)
{
    va_list args;
    const char *prompt;

    (void)pamh;
    (void)style;
    assert(strcmp(format, "%s") == 0);
    va_start(args, format);
    prompt = va_arg(args, const char *);
    va_end(args);
    assert(snprintf(captured_prompt, sizeof(captured_prompt), "%s", prompt) > 0);
    *response = strdup(response_text);
    return *response == NULL ? PAM_AUTH_ERR : PAM_SUCCESS;
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

int oath_base32_decode(const char *input, size_t input_length,
                       char **output, size_t *output_length)
{
    assert(input != NULL && input_length >= 16U);
    *output = malloc(4U);
    if (*output == NULL) {
        return OATH_CRYPTO_ERROR;
    }
    memcpy(*output, "seed", 4U);
    *output_length = 4U;
    return OATH_OK;
}

int oath_totp_validate3(const char *secret, size_t secret_length, time_t now,
                        unsigned int step, time_t start_offset, size_t window,
                        int *position, uint64_t *counter, const char *otp)
{
    (void)now;
    (void)start_offset;
    (void)position;
    assert(secret != NULL && secret_length == 4U);
    assert(step == 30U && window == 1U);
    assert(strcmp(otp, response_text) == 0);
    *counter = UINT64_C(12345);
    oath_validate_calls++;
    return 0;
}

int totp_replay_check_and_store(const char *module_tag, uid_t user_id,
                                uint64_t counter)
{
    (void)user_id;
    assert(counter == UINT64_C(12345));
    assert(snprintf(captured_replay_tag, sizeof(captured_replay_tag), "%s",
                    module_tag) > 0);
    return replay_status;
}

static void test_each_slot(void)
{
    struct pam_handle handle = {0};
    const char *argv[] = {"slots=4"};

    for (size_t i = 0U; i < PTSC_MAX_SLOTS; i++) {
        char expected_prompt[32];

        reset_state();
        selected_index = i;
        assert(pam_sm_authenticate(&handle, 0, 1, argv) == PAM_SUCCESS);
        assert(snprintf(expected_prompt, sizeof(expected_prompt),
                        "TOTP del slot %c: ", test_slots[i].id) > 0);
        assert(strcmp(captured_prompt, expected_prompt) == 0);
        assert(strcmp(captured_replay_tag, test_slots[i].replay_tag) == 0);
        assert(fail_delay_calls == 0U);
        assert(oath_validate_calls == 1U);
    }
}

static void test_fail_closed_paths(void)
{
    struct pam_handle handle = {0};
    const char *valid[] = {"slots=2"};
    const char *invalid[] = {"slots=5"};

    reset_state();
    assert(pam_sm_authenticate(&handle, 0, 1, invalid) == PAM_SERVICE_ERR);
    assert(oath_validate_calls == 0U);

    reset_state();
    response_text = "12X456";
    assert(pam_sm_authenticate(&handle, 0, 1, valid) == PAM_AUTH_ERR);
    assert(oath_validate_calls == 0U);
    assert(fail_delay_calls == 1U);

    reset_state();
    secret_status = PTSC_SECRET_ERROR;
    assert(pam_sm_authenticate(&handle, 0, 1, valid) == PAM_AUTH_ERR);
    assert(oath_validate_calls == 1U);
    assert(captured_replay_tag[0] == '\0');
    assert(fail_delay_calls == 1U);

    reset_state();
    replay_status = TOTP_REPLAY_DETECTED;
    assert(pam_sm_authenticate(&handle, 0, 1, valid) == PAM_AUTH_ERR);
    assert(fail_delay_calls == 1U);
}

int main(void)
{
    test_each_slot();
    test_fail_closed_paths();
    puts("module integration tests passed");
    return 0;
}
