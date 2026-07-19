#include "../rollover.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void check(int condition, const char *name)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

static void test_counters(void)
{
    uint64_t counter = UINT64_C(0);

    check(ptr_counter_from_wall((time_t)0, &counter) == 0 && counter == 0U,
          "epoch counter");
    check(ptr_counter_from_wall((time_t)29, &counter) == 0 && counter == 0U,
          "end of first period");
    check(ptr_counter_from_wall((time_t)30, &counter) == 0 && counter == 1U,
          "second period");
    check(ptr_counter_from_wall((time_t)-1, &counter) != 0,
          "negative wall rejected");
    check(ptr_counter_from_wall((time_t)30, NULL) != 0,
          "null counter rejected");
}

static void test_plan(void)
{
    const struct timespec mono = {.tv_sec = (time_t)100, .tv_nsec = 123L};
    struct timespec wall = {.tv_sec = (time_t)60, .tv_nsec = 0L};
    struct timespec boundary;
    struct timespec deadline;

    check(ptr_plan_second_step(&wall, &mono, UINT64_C(2), &boundary,
                               &deadline) == 0,
          "plan at boundary");
    check(boundary.tv_sec == (time_t)130 && boundary.tv_nsec == 123L,
          "boundary waits full period");
    check(deadline.tv_sec == (time_t)155 && deadline.tv_nsec == 123L,
          "deadline includes grace");

    wall.tv_sec = (time_t)75;
    check(ptr_plan_second_step(&wall, &mono, UINT64_C(2), &boundary,
                               &deadline) == 0,
          "plan at period center");
    check(boundary.tv_sec == (time_t)115 && deadline.tv_sec == (time_t)140,
          "center waits half period");

    wall.tv_sec = (time_t)89;
    check(ptr_plan_second_step(&wall, &mono, UINT64_C(2), &boundary,
                               &deadline) == 0,
          "plan at period end");
    check(boundary.tv_sec == (time_t)101 && deadline.tv_sec == (time_t)126,
          "one second boundary");
    wall.tv_sec = (time_t)90;
    check(ptr_plan_second_step(&wall, &mono, UINT64_C(2), &boundary,
                               &deadline) != 0,
          "mismatched first counter rejected");
    wall.tv_sec = (time_t)60;
    check(ptr_plan_second_step(&wall, &mono, UINT64_MAX, &boundary,
                               &deadline) != 0,
          "maximum counter rejected");

    wall.tv_sec = (time_t)89;
    wall.tv_nsec = 999000000L;
    {
        const struct timespec precise_mono = {
            .tv_sec = (time_t)100, .tv_nsec = 500000000L};
        check(ptr_plan_second_step(&wall, &precise_mono, UINT64_C(2),
                                   &boundary, &deadline) == 0,
              "subsecond plan accepted");
        check(boundary.tv_sec == (time_t)100 &&
                  boundary.tv_nsec == 501000000L,
              "subsecond boundary is precise");
    }
}

static void test_second_window(void)
{
    const struct timespec deadline = {.tv_sec = (time_t)200, .tv_nsec = 0L};
    struct timespec now = {.tv_sec = (time_t)199, .tv_nsec = 999999999L};

    check(ptr_second_step_is_timely((time_t)90, &now, UINT64_C(2),
                                    &deadline) == 1,
          "N plus one accepted before deadline");
    check(ptr_second_step_is_timely((time_t)60, &now, UINT64_C(2),
                                    &deadline) == 0,
          "same period rejected");
    check(ptr_second_step_is_timely((time_t)120, &now, UINT64_C(2),
                                    &deadline) == 0,
          "skipped period rejected");
    now.tv_sec = (time_t)200;
    now.tv_nsec = 1L;
    check(ptr_second_step_is_timely((time_t)90, &now, UINT64_C(2),
                                    &deadline) == 0,
          "late response rejected");
}

static void test_otp_text(void)
{
    check(ptr_validate_otp_text("012345", 6U) == 0, "six digits accepted");
    check(ptr_validate_otp_text("12345", 5U) != 0, "short code rejected");
    check(ptr_validate_otp_text("1234567", 7U) != 0, "long code rejected");
    check(ptr_validate_otp_text("12a456", 6U) != 0,
          "non digit rejected");
    check(ptr_validate_otp_text(NULL, 6U) != 0, "null code rejected");
}

int main(void)
{
    test_counters();
    test_plan();
    test_second_window();
    test_otp_text();

    if (failures != 0) return EXIT_FAILURE;
    puts("rollover core tests passed");
    return EXIT_SUCCESS;
}
