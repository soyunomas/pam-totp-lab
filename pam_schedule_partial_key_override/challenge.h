#ifndef SPK_CHALLENGE_H
#define SPK_CHALLENGE_H

#include <stddef.h>
#include <sys/types.h>

#define SPK_CHALLENGE_COUNT 3U
#define SPK_CHALLENGE_OK 0
#define SPK_CHALLENGE_ERROR (-1)
#define SPK_CHALLENGE_EXHAUSTED 1

int spk_reserve_challenge_at(int directory_fd, uid_t expected_owner,
                             uid_t user_id, const char *username,
                             const char *service, const char *authorizer,
                             const unsigned char key_id[32], size_t pass_len,
                             size_t positions[SPK_CHALLENGE_COUNT]);
int spk_reserve_challenge(uid_t user_id, const char *username,
                          const char *service, const char *authorizer,
                          const unsigned char key_id[32], size_t pass_len,
                          size_t positions[SPK_CHALLENGE_COUNT]);

#endif
