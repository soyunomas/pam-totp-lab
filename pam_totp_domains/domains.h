#ifndef PAM_TOTP_DOMAINS_DOMAINS_H
#define PAM_TOTP_DOMAINS_DOMAINS_H

#include <stddef.h>

#define PTD_SECRET_DIRECTORY ".pam_totp_domains"
#define PTD_MIN_SECRET_LEN 16U
#define PTD_MAX_SECRET_LEN 128U
#define PTD_MAX_SERVICE_LEN 64U
#define PTD_MAX_REPLAY_TAG_LEN 32U

struct ptd_domain {
    const char *service;
    const char *secret_file;
    const char *label;
    const char *replay_tag;
};

/* Return the immutable policy entry for an exact PAM service name. */
const struct ptd_domain *ptd_domain_for_service(const char *service);

/* Accept only unpadded, uppercase RFC 4648 Base32 characters. */
int ptd_validate_base32_secret(const char *secret, size_t length);

#endif
