#include <liboath/oath.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STEP_SECONDS 30U
#define OTP_DIGITS 6U

static int generate(const char *secret, size_t secret_len, time_t when,
                    char output[OTP_DIGITS + 1U])
{
    return oath_totp_generate(secret, secret_len, when, STEP_SECONDS, 0,
                              OTP_DIGITS, output);
}

static int expect_position(const char *secret, size_t secret_len, time_t now,
                           size_t window, const char *otp,
                           int expected_result, int expected_position,
                           uint64_t expected_counter,
                           const char *name)
{
    int position = -1;
    uint64_t counter = 0U;
    int result = oath_totp_validate3(secret, secret_len, now, STEP_SECONDS, 0,
                                     window, &position, &counter, otp);

    if (result != expected_result || position != expected_position ||
        counter != expected_counter) {
        fprintf(stderr,
                "%s: result=%d position=%d counter=%llu expected_result=%d "
                "expected_position=%d expected_counter=%llu\n",
                name, result, position, (unsigned long long)counter,
                expected_result, expected_position,
                (unsigned long long)expected_counter);
        return -1;
    }
    return 0;
}

int main(void)
{
    const char secret[] = "12345678901234567890";
    const time_t now = (time_t)1234567890;
    char previous[OTP_DIGITS + 1U] = {0};
    char current[OTP_DIGITS + 1U] = {0};
    char next[OTP_DIGITS + 1U] = {0};
    const uint64_t current_counter = (uint64_t)now / STEP_SECONDS;

    if (oath_init() != OATH_OK ||
        generate(secret, strlen(secret), now - STEP_SECONDS, previous) !=
            OATH_OK ||
        generate(secret, strlen(secret), now, current) != OATH_OK ||
        generate(secret, strlen(secret), now + STEP_SECONDS, next) !=
            OATH_OK) {
        fputs("failed to initialize deterministic TOTP vectors\n", stderr);
        return EXIT_FAILURE;
    }

    if (expect_position(secret, strlen(secret), now, 1U, current, 0, 0,
                        current_counter,
                        "current") != 0 ||
        expect_position(secret, strlen(secret), now, 1U, next, 1, 1,
                        current_counter + 1U,
                        "next") != 0 ||
        expect_position(secret, strlen(secret), now, 1U, previous, 1, -1,
                        current_counter - 1U,
                        "previous") != 0) {
        oath_done();
        return EXIT_FAILURE;
    }

    oath_done();
    puts("All liboath window tests passed.");
    return EXIT_SUCCESS;
}
