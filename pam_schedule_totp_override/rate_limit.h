#ifndef PSO_RATE_LIMIT_H
#define PSO_RATE_LIMIT_H

#include <stdint.h>
#include <sys/types.h>

#define PSO_RATE_ERROR (-1)
#define PSO_RATE_ALLOWED 0
#define PSO_RATE_BLOCKED 1

#define PSO_RATE_MAX_FAILURES 5U
#define PSO_RATE_WINDOW_SECONDS UINT64_C(300)
#define PSO_RATE_BLOCK_SECONDS UINT64_C(300)

int pso_validate_service(const char *service);
int pso_monotonic_seconds(uint64_t *seconds_out);
int pso_rate_check_at(int state_dir_fd, uid_t expected_owner, uid_t user_id,
                      const char *service, uint64_t now);
int pso_rate_record_failure_at(int state_dir_fd, uid_t expected_owner,
                               uid_t user_id, const char *service,
                               uint64_t now);
int pso_rate_reset_at(int state_dir_fd, uid_t expected_owner, uid_t user_id,
                      const char *service);
int pso_rate_check(uid_t user_id, const char *service, uint64_t now);
int pso_rate_record_failure(uid_t user_id, const char *service, uint64_t now);
int pso_rate_reset(uid_t user_id, const char *service);

#endif
