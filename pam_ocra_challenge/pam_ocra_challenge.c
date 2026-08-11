#define _GNU_SOURCE

#include "ocra_core.h"
#include "rate_limit.h"
#include "scope.h"
#include "secret_store.h"
#include "secure_memory.h"

#include <pwd.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#define OCRA_PAM_FAIL_DELAY_US 3000000U
#define OCRA_PAM_RESPONSE_SCAN_LIMIT 512U

static const unsigned char fake_secret[OCRA_SECRET_BYTES] = {
    0x94U, 0x24U, 0xc3U, 0x8bU, 0xd7U, 0x2fU, 0x6aU, 0xe1U,
    0x5dU, 0x09U, 0xa8U, 0xf3U, 0x61U, 0xbcU, 0x47U, 0x0eU,
    0x83U, 0xdaU, 0x29U, 0x75U, 0x10U, 0xeeU, 0x58U, 0xb6U,
    0x3cU, 0x91U, 0x07U, 0xf4U, 0xa2U, 0x6dU, 0xcbU, 0x35U,
};
static const char fake_key_id[OCRA_KEY_ID_HEX_LENGTH + 1U] =
    "ffffffffffffffff";

static int resolve_uid(const char *username, uid_t *uid_out)
{
    long configured_size;
    size_t buffer_size;
    char *buffer;
    struct passwd entry;
    struct passwd *result = NULL;
    int status = -1;

    if (username == NULL || uid_out == NULL) {
        return -1;
    }
    configured_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    buffer_size = configured_size > 0 ? (size_t)configured_size : 16384U;
    if (buffer_size == 0U || buffer_size > 1048576U) {
        return -1;
    }
    buffer = calloc(1U, buffer_size);
    if (buffer == NULL) {
        return -1;
    }
    if (getpwnam_r(username, &entry, buffer, buffer_size, &result) == 0 &&
        result != NULL) {
        *uid_out = entry.pw_uid;
        status = 0;
    }
    secure_memory_clear(buffer, buffer_size);
    free(buffer);
    return status;
}

static int response_is_valid(const char *response, size_t length)
{
    size_t index;

    if (response == NULL || length != OCRA_RESPONSE_DIGITS) {
        return 0;
    }
    for (index = 0U; index < length; ++index) {
        if (response[index] < '0' || response[index] > '9') {
            return 0;
        }
    }
    return 1;
}

static int constant_time_equal(const char *left, const char *right,
                               size_t length)
{
    unsigned char difference = 0U;
    size_t index;

    for (index = 0U; index < length; ++index) {
        difference |= (unsigned char)left[index] ^ (unsigned char)right[index];
    }
    return difference == 0U;
}

static void clear_and_free_response(char **response, size_t length)
{
    if (response == NULL || *response == NULL) {
        return;
    }
    secure_memory_clear(*response, length);
    free(*response);
    *response = NULL;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv)
{
    const char *username = NULL;
    const void *service_item = NULL;
    const char *service;
    struct ocra_secret_record record;
    char challenge[OCRA_CHALLENGE_DIGITS + 1U];
    char expected[OCRA_RESPONSE_CAPACITY];
    char message[128U];
    char *response = NULL;
    size_t response_length = 0U;
    uid_t uid = (uid_t)-1;
    int fake_mode = 0;
    int message_length;
    int result = PAM_AUTH_ERR;

    (void)flags;
    (void)argv;
    ocra_secret_record_clear(&record);
    (void)memset(challenge, 0, sizeof(challenge));
    (void)memset(expected, 0, sizeof(expected));
    (void)memset(message, 0, sizeof(message));

    if (pamh == NULL || argc != 0) {
        return PAM_SERVICE_ERR;
    }
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS ||
        username == NULL ||
        pam_get_item(pamh, PAM_SERVICE, &service_item) != PAM_SUCCESS ||
        service_item == NULL) {
        goto cleanup;
    }
    service = (const char *)service_item;
    if (ocra_scope_validate_service(service) != 0) {
        result = PAM_SERVICE_ERR;
        goto cleanup;
    }

    if (resolve_uid(username, &uid) != 0 ||
        ocra_secret_store_load(uid, service, &record) != 0) {
        fake_mode = 1;
        (void)memcpy(record.secret, fake_secret, sizeof(fake_secret));
        (void)memcpy(record.key_id, fake_key_id, sizeof(fake_key_id));
    }
    if (ocra_rate_limit_reserve(uid, service, record.key_id, challenge) != 0) {
        syslog(LOG_NOTICE, "pam_ocra_challenge: authentication unavailable");
        goto cleanup;
    }
    message_length = snprintf(message, sizeof(message),
                              "Desafío OCRA para %s: %s", service,
                              challenge);
    if (message_length < 0 || (size_t)message_length >= sizeof(message) ||
        pam_info(pamh, "%s", message) != PAM_SUCCESS ||
        pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &response, "%s",
                   "Respuesta OCRA: ") != PAM_SUCCESS) {
        syslog(LOG_NOTICE, "pam_ocra_challenge: conversation failed");
        goto cleanup;
    }
    if (response != NULL) {
        response_length =
            strnlen(response, OCRA_PAM_RESPONSE_SCAN_LIMIT);
    }
    if (ocra_compute_response(record.secret, OCRA_SECRET_BYTES, challenge,
                              OCRA_CHALLENGE_DIGITS, expected,
                              sizeof(expected)) != 0) {
        syslog(LOG_ERR, "pam_ocra_challenge: response computation failed");
        goto cleanup;
    }
    if (fake_mode == 0 && response_is_valid(response, response_length) &&
        constant_time_equal(expected, response, OCRA_RESPONSE_DIGITS) &&
        ocra_rate_limit_reset(uid, service, record.key_id) == 0) {
        result = PAM_SUCCESS;
    }

cleanup:
    clear_and_free_response(&response, response_length);
    secure_memory_clear(expected, sizeof(expected));
    secure_memory_clear(challenge, sizeof(challenge));
    secure_memory_clear(message, sizeof(message));
    ocra_secret_record_clear(&record);
    if (result != PAM_SUCCESS && result != PAM_SERVICE_ERR) {
        (void)pam_fail_delay(pamh, OCRA_PAM_FAIL_DELAY_US);
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
