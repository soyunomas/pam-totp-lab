#define _POSIX_C_SOURCE 200809L

#include "rollover_clock.h"

#include <errno.h>

int ptr_clock_wall_now(struct timespec *out)
{
    return out != NULL && clock_gettime(CLOCK_REALTIME, out) == 0 ? 0 : -1;
}

int ptr_clock_monotonic_now(struct timespec *out)
{
    return out != NULL && clock_gettime(CLOCK_MONOTONIC, out) == 0 ? 0 : -1;
}

int ptr_clock_wait_until(const struct timespec *deadline)
{
    int result;

    if (deadline == NULL) return -1;
    result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, deadline, NULL);
    return result == 0 ? 0 : -1;
}
