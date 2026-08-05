#ifndef OCRA_RATE_LIMIT_H
#define OCRA_RATE_LIMIT_H

#include "challenge.h"

#include <sys/types.h>

int ocra_rate_limit_reserve(uid_t uid, const char *service,
                            const char *key_id,
                            char challenge[OCRA_CHALLENGE_DIGITS + 1U]);
int ocra_rate_limit_reserve_at(
    int root_fd, const char *uid_text, const char *service, const char *key_id,
    char challenge[OCRA_CHALLENGE_DIGITS + 1U]);
int ocra_rate_limit_reset(uid_t uid, const char *service, const char *key_id);
int ocra_rate_limit_reset_at(int root_fd, const char *uid_text,
                             const char *service, const char *key_id);
int ocra_rate_limit_remove(uid_t uid, const char *service, const char *key_id);
int ocra_rate_limit_remove_at(int root_fd, const char *uid_text,
                              const char *service, const char *key_id);

#ifdef OCRA_TESTING
#include <time.h>

typedef int (*ocra_rate_limit_clock_provider)(clockid_t clock_id,
                                               struct timespec *value);
typedef int (*ocra_rate_limit_challenge_provider)(
    char output[OCRA_CHALLENGE_DIGITS + 1U]);
typedef int (*ocra_rate_limit_state_close_provider)(int fd);

void ocra_rate_limit_set_clock_provider_for_tests(
    ocra_rate_limit_clock_provider provider);
void ocra_rate_limit_reset_clock_provider_for_tests(void);
void ocra_rate_limit_set_challenge_provider_for_tests(
    ocra_rate_limit_challenge_provider provider);
void ocra_rate_limit_reset_challenge_provider_for_tests(void);
void ocra_rate_limit_set_expected_owner_for_tests(uid_t uid, gid_t gid);
void ocra_rate_limit_reset_expected_owner_for_tests(void);
void ocra_rate_limit_set_state_close_provider_for_tests(
    ocra_rate_limit_state_close_provider provider);
void ocra_rate_limit_reset_state_close_provider_for_tests(void);
int ocra_rate_limit_prepare_directory_at_for_tests(int parent_fd,
                                                   const char *name);
#endif

#endif
