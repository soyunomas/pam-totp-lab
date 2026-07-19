#ifndef PAM_TOTP_LAB_USER_TOTP_SECRET_H
#define PAM_TOTP_LAB_USER_TOTP_SECRET_H

#include <stddef.h>
#include <sys/types.h>

#define USER_TOTP_SECRET_OK 0
#define USER_TOTP_SECRET_NOT_FOUND 1
#define USER_TOTP_SECRET_ERROR (-1)

#define USER_TOTP_SECRET_MIN_LENGTH 16U
#define USER_TOTP_SECRET_MAX_LENGTH 128U

void user_totp_secure_memzero(void *buffer, size_t length);
int user_totp_validate_base32(const char *secret, size_t length);
int user_totp_secret_read_at(int directory_fd, const char *filename,
                             uid_t expected_owner, char *secret_out,
                             size_t secret_capacity);
int user_totp_secret_get(const char *username, const char *filename,
                         char *secret_out, size_t secret_capacity,
                         uid_t *uid_out);

#endif
