#ifndef PAM_TOTP_ROLLOVER_CORE_H
#define PAM_TOTP_ROLLOVER_CORE_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define PTR_TOTP_STEP_SECONDS 30U
#define PTR_SECOND_GRACE_SECONDS 25U
#define PTR_OTP_DIGITS 6U

int ptr_counter_from_wall(time_t wall, uint64_t *counter_out);
int ptr_plan_second_step(const struct timespec *wall,
                         const struct timespec *monotonic,
                         uint64_t first_counter,
                         struct timespec *boundary_out,
                         struct timespec *deadline_out);
int ptr_second_step_is_timely(time_t wall, const struct timespec *monotonic,
                              uint64_t first_counter,
                              const struct timespec *deadline);
int ptr_validate_otp_text(const char *otp, size_t length);

#endif
