#include "scope.h"

#include <stdint.h>
#include <stddef.h>

int ocra_scope_parse_uid(const char *text, uid_t *uid)
{
    uintmax_t value = 0U;
    size_t index;

    if (text == NULL || uid == NULL || text[0] == '\0' ||
        (text[0] == '0' && text[1] != '\0')) {
        return -1;
    }
    for (index = 0U; text[index] != '\0'; ++index) {
        unsigned int digit;

        if (index >= OCRA_UID_TEXT_MAX_LENGTH || text[index] < '0' ||
            text[index] > '9') {
            return -1;
        }
        digit = (unsigned int)(text[index] - '0');
        if (value > (UINT32_MAX - digit) / 10U) {
            return -1;
        }
        value = (value * 10U) + digit;
    }
    *uid = (uid_t)value;
    if ((uintmax_t)*uid != value) {
        *uid = (uid_t)0;
        return -1;
    }
    return 0;
}

int ocra_scope_validate_service(const char *service)
{
    size_t length;

    if (service == NULL || service[0] == '\0') {
        return -1;
    }
    for (length = 0U; service[length] != '\0'; ++length) {
        unsigned char byte = (unsigned char)service[length];

        if (length >= OCRA_SERVICE_MAX_LENGTH ||
            !((byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') ||
              (byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
              (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              byte == (unsigned char)'_' || byte == (unsigned char)'-')) {
            return -1;
        }
    }
    return 0;
}
