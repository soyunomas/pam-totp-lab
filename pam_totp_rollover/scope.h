#ifndef PAM_TOTP_ROLLOVER_SCOPE_H
#define PAM_TOTP_ROLLOVER_SCOPE_H

#include <stddef.h>

#define PTR_SERVICE_MAX_LENGTH 64U
#define PTR_REPLAY_TAG_CAPACITY 32U

int ptr_validate_service(const char *service);
int ptr_make_replay_tag(const char *service, const unsigned char *secret,
                        size_t secret_length,
                        char out[PTR_REPLAY_TAG_CAPACITY]);

#endif
