#ifndef PAM_TOTP_DOMAINS_SECRET_FILE_H
#define PAM_TOTP_DOMAINS_SECRET_FILE_H

#include "domains.h"

#include <stddef.h>
#include <sys/types.h>

enum ptd_secret_status {
    PTD_SECRET_ERROR = -1,
    PTD_SECRET_OK = 0,
    PTD_SECRET_NOT_FOUND = 1
};

int ptd_read_secret_at(int home_fd, uid_t expected_owner,
                       const struct ptd_domain *domain, char *secret_out,
                       size_t secret_out_size);

#endif
