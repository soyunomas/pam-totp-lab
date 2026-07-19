#ifndef PAM_TOTP_ROLLOVER_CLOCK_H
#define PAM_TOTP_ROLLOVER_CLOCK_H

#include <time.h>

int ptr_clock_wall_now(struct timespec *out);
int ptr_clock_monotonic_now(struct timespec *out);
int ptr_clock_wait_until(const struct timespec *deadline);

#endif
