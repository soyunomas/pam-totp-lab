#ifndef PAM_TOTP_SHUFFLE_SECRET_H
#define PAM_TOTP_SHUFFLE_SECRET_H

#include <stddef.h>
#include <sys/types.h>

#define PTS_SECRET_FILE ".pam_totp_shuffle"
#define PTS_MIN_SECRET_LENGTH 16U
#define PTS_MAX_SECRET_LENGTH 128U

#define PTS_SECRET_OK 0
#define PTS_SECRET_NOT_FOUND 1
#define PTS_SECRET_ERROR (-1)

int pts_validate_base32_secret(const char *secret, size_t length);
int pts_read_secret_at(int directory_fd, const char *name, uid_t expected_owner,
                       char *secret_out, size_t secret_out_size);
int pts_get_user_secret(const char *username, char *secret_out,
                        size_t secret_out_size, uid_t *uid_out);
void pts_secure_memzero(void *buffer, size_t length);

#endif
