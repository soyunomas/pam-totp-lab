#ifndef PAM_TOTP_SLOT_CHALLENGE_SECRET_H
#define PAM_TOTP_SLOT_CHALLENGE_SECRET_H

#include <stddef.h>
#include <sys/types.h>

#define PTSC_SECRET_DIRECTORY ".pam_totp_slots"
#define PTSC_MIN_SECRET_LEN 16U
#define PTSC_MAX_SECRET_LEN 128U

#define PTSC_SECRET_OK 0
#define PTSC_SECRET_NOT_FOUND 1
#define PTSC_SECRET_ERROR (-1)

void ptsc_secure_memzero(void *buffer, size_t length);
int ptsc_validate_base32_secret(const char *secret, size_t length);
int ptsc_read_slot_secret(const char *home_directory, uid_t expected_owner,
                          size_t slot_index, char *secret_out,
                          size_t secret_capacity);

#endif
