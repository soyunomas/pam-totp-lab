#ifndef PAM_TOTP_SLOT_CHALLENGE_CONFIG_H
#define PAM_TOTP_SLOT_CHALLENGE_CONFIG_H

#include <stddef.h>

int ptsc_parse_options(int argc, const char *const argv[],
                       size_t *slot_count_out);

#endif
