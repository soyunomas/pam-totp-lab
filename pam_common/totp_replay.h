#ifndef PAM_TOTP_LAB_TOTP_REPLAY_H
#define PAM_TOTP_LAB_TOTP_REPLAY_H

#include <stdint.h>
#include <sys/types.h>

#define TOTP_REPLAY_ACCEPTED 0
#define TOTP_REPLAY_DETECTED 1
#define TOTP_REPLAY_ERROR (-1)

/*
 * Atomically rejects counters already accepted for this module and user.
 * Production state is kept below /run/pam-totp-lab and requires EUID 0.
 */
int totp_replay_check_and_store(const char *module_tag, uid_t user_id,
                                uint64_t counter);

#ifdef TOTP_REPLAY_TESTING
/* Test-only entry point using an already-open, private state directory. */
int totp_replay_check_and_store_at(int state_dir_fd, uid_t expected_owner,
                                   const char *module_tag, uid_t user_id,
                                   uint64_t counter);
#endif

#endif
