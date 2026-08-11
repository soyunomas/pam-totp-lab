#include "../rate_limit.h"
#include "../secret_store.h"
#include "../secure_memory.h"

#include <pwd.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>

#define INTEGRATION_UID ((uid_t)4242)

int ocra_integration_getpwnam_r(const char *name, struct passwd *entry,
                                char *buffer, size_t buffer_length,
                                struct passwd **result)
{
    static const char expected_name[] = "isolated-user";

    if (name == NULL || entry == NULL || buffer == NULL || result == NULL ||
        strcmp(name, expected_name) != 0 || buffer_length < sizeof(expected_name)) {
        if (result != NULL) {
            *result = NULL;
        }
        return 0;
    }
    (void)memcpy(buffer, expected_name, sizeof(expected_name));
    (void)memset(entry, 0, sizeof(*entry));
    entry->pw_name = buffer;
    entry->pw_uid = INTEGRATION_UID;
    *result = entry;
    return 0;
}

int ocra_secret_store_load(uid_t uid, const char *service,
                           struct ocra_secret_record *record)
{
    static const unsigned char secret[] =
        "12345678901234567890123456789012";

    if (uid != INTEGRATION_UID || service == NULL ||
        strcmp(service, "ocra-integration") != 0 || record == NULL) {
        return -1;
    }
    (void)memcpy(record->secret, secret, OCRA_SECRET_BYTES);
    (void)memcpy(record->key_id, "0011223344556677",
                 OCRA_KEY_ID_HEX_LENGTH + 1U);
    return 0;
}

void ocra_secret_record_clear(struct ocra_secret_record *record)
{
    if (record != NULL) {
        secure_memory_clear(record, sizeof(*record));
    }
}

int ocra_rate_limit_reserve(uid_t uid, const char *service,
                            const char *key_id,
                            char challenge[OCRA_CHALLENGE_DIGITS + 1U])
{
    if (uid != INTEGRATION_UID || service == NULL || key_id == NULL ||
        challenge == NULL || strcmp(service, "ocra-integration") != 0 ||
        strcmp(key_id, "0011223344556677") != 0) {
        return -1;
    }
    (void)memcpy(challenge, "1234567890", OCRA_CHALLENGE_DIGITS + 1U);
    return 0;
}

int ocra_rate_limit_reset(uid_t uid, const char *service, const char *key_id)
{
    return uid == INTEGRATION_UID && service != NULL && key_id != NULL &&
                   strcmp(service, "ocra-integration") == 0 &&
                   strcmp(key_id, "0011223344556677") == 0
               ? 0
               : -1;
}
