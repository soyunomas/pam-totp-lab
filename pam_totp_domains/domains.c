#include "domains.h"

#include <string.h>

static size_t bounded_length(const char *value, size_t limit)
{
    size_t length = 0U;
    while (length < limit && value[length] != '\0') length++;
    return length;
}

static const struct ptd_domain domains[] = {
    {"sshd", "sshd.secret", "SSH", "ptd_sshd"},
    {"sudo", "sudo.secret", "SUDO", "ptd_sudo"},
    {"login", "login.secret", "LOGIN", "ptd_login"},
    {"su", "su.secret", "SU", "ptd_su"},
};

const struct ptd_domain *ptd_domain_for_service(const char *service)
{
    size_t length;

    if (service == NULL) return NULL;
    length = bounded_length(service, PTD_MAX_SERVICE_LEN + 1U);
    if (length == 0U || length > PTD_MAX_SERVICE_LEN) return NULL;

    for (size_t i = 0U; i < sizeof(domains) / sizeof(domains[0]); i++) {
        if (strcmp(service, domains[i].service) == 0) return &domains[i];
    }
    return NULL;
}

int ptd_validate_base32_secret(const char *secret, size_t length)
{
    size_t remainder;

    if (secret == NULL || length < PTD_MIN_SECRET_LEN ||
        length > PTD_MAX_SECRET_LEN) return -1;

    remainder = length % 8U;
    if (remainder == 1U || remainder == 3U || remainder == 6U) return -1;

    for (size_t i = 0U; i < length; i++) {
        unsigned char value = (unsigned char)secret[i];
        if (!((value >= (unsigned char)'A' && value <= (unsigned char)'Z') ||
              (value >= (unsigned char)'2' && value <= (unsigned char)'7'))) {
            return -1;
        }
    }
    return 0;
}
