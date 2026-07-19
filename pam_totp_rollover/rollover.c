#include "rollover.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

static int valid_timespec(const struct timespec *value)
{
    return value != NULL && value->tv_sec >= (time_t)0 &&
                   value->tv_nsec >= 0 && value->tv_nsec < 1000000000L
               ? 0
               : -1;
}

static int add_seconds(const struct timespec *base, unsigned int seconds,
                       struct timespec *result)
{
    uint64_t base_seconds;

    if (valid_timespec(base) != 0 || result == NULL) return -1;
    base_seconds = (uint64_t)base->tv_sec;
    if (base_seconds > (uint64_t)INT64_MAX - (uint64_t)seconds) return -1;
    result->tv_sec = (time_t)(base_seconds + (uint64_t)seconds);
    if (result->tv_sec < base->tv_sec) return -1;
    result->tv_nsec = base->tv_nsec;
    return 0;
}

static int timespec_after(const struct timespec *left,
                          const struct timespec *right)
{
    if (left->tv_sec != right->tv_sec) return left->tv_sec > right->tv_sec;
    return left->tv_nsec > right->tv_nsec;
}

int ptr_counter_from_wall(time_t wall, uint64_t *counter_out)
{
    if (counter_out == NULL || wall < (time_t)0) return -1;
    *counter_out = (uint64_t)wall / (uint64_t)PTR_TOTP_STEP_SECONDS;
    return 0;
}

int ptr_plan_second_step(const struct timespec *wall,
                         const struct timespec *monotonic,
                         uint64_t first_counter,
                         struct timespec *boundary_out,
                         struct timespec *deadline_out)
{
    uint64_t current_counter;
    uint64_t wall_seconds;
    unsigned int until_boundary;

    if (boundary_out == NULL || deadline_out == NULL ||
        valid_timespec(wall) != 0 ||
        ptr_counter_from_wall(wall->tv_sec, &current_counter) != 0 ||
        current_counter != first_counter || first_counter == UINT64_MAX ||
        valid_timespec(monotonic) != 0) {
        return -1;
    }
    wall_seconds = (uint64_t)wall->tv_sec;
    until_boundary = PTR_TOTP_STEP_SECONDS -
                     (unsigned int)(wall_seconds % PTR_TOTP_STEP_SECONDS);
    if (add_seconds(monotonic, until_boundary, boundary_out) != 0) return -1;
    boundary_out->tv_nsec -= wall->tv_nsec;
    if (boundary_out->tv_nsec < 0) {
        if (boundary_out->tv_sec == (time_t)0) return -1;
        boundary_out->tv_sec--;
        boundary_out->tv_nsec += 1000000000L;
    }
    if (add_seconds(boundary_out, PTR_SECOND_GRACE_SECONDS, deadline_out) != 0) {
        return -1;
    }
    return 0;
}

int ptr_second_step_is_timely(time_t wall, const struct timespec *monotonic,
                              uint64_t first_counter,
                              const struct timespec *deadline)
{
    uint64_t current_counter;

    if (first_counter == UINT64_MAX || valid_timespec(monotonic) != 0 ||
        valid_timespec(deadline) != 0 ||
        ptr_counter_from_wall(wall, &current_counter) != 0 ||
        current_counter != first_counter + UINT64_C(1) ||
        timespec_after(monotonic, deadline)) {
        return 0;
    }
    return 1;
}

int ptr_validate_otp_text(const char *otp, size_t length)
{
    if (otp == NULL || length != PTR_OTP_DIGITS) return -1;
    for (size_t i = 0U; i < length; i++) {
        if (otp[i] < '0' || otp[i] > '9') return -1;
    }
    return 0;
}
