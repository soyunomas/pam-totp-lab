#include "../challenge.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct random_script {
    const unsigned char *bytes;
    size_t length;
    size_t offset;
    size_t maximum_chunk;
    unsigned int interruptions_remaining;
    int permanent_failure;
};

static struct random_script *current_script;

static void require(int condition, const char *message)
{
    if (!condition) {
        (void)fprintf(stderr, "test failure: %s\n", message);
        exit(EXIT_FAILURE);
    }
}

static ssize_t scripted_getrandom(void *buffer, size_t length, int flags)
{
    size_t available;
    size_t count;

    require(flags == 0, "random provider must receive no flags");
    require(current_script != NULL, "random provider needs an active script");

    if (current_script->interruptions_remaining != 0U) {
        --current_script->interruptions_remaining;
        errno = EINTR;
        return -1;
    }
    if (current_script->permanent_failure != 0) {
        errno = EIO;
        return -1;
    }
    if (current_script->offset == current_script->length) {
        errno = EIO;
        return -1;
    }

    available = current_script->length - current_script->offset;
    count = length < available ? length : available;
    if (current_script->maximum_chunk != 0U &&
        count > current_script->maximum_chunk) {
        count = current_script->maximum_chunk;
    }
    memcpy(buffer, current_script->bytes + current_script->offset, count);
    current_script->offset += count;
    return (ssize_t)count;
}

static void install_script(struct random_script *script)
{
    current_script = script;
    ocra_challenge_set_random_provider_for_tests(scripted_getrandom);
}

static void reset_provider(void)
{
    ocra_challenge_reset_random_provider_for_tests();
    current_script = NULL;
}

static void test_minimum_value_preserves_all_zeroes(void)
{
    static const uint64_t values[] = {UINT64_C(0)};
    struct random_script script = {(const unsigned char *)values,
                                   sizeof(values), 0U, 0U, 0U, 0};
    char output[OCRA_CHALLENGE_DIGITS + 1U];

    install_script(&script);
    require(ocra_generate_challenge(output) == 0,
            "minimum random value must generate a challenge");
    require(strcmp(output, "0000000000") == 0,
            "minimum value must preserve ten zeroes");
    reset_provider();
}

static void test_maximum_challenge_value_is_representable(void)
{
    static const uint64_t values[] = {UINT64_C(9999999999)};
    struct random_script script = {(const unsigned char *)values,
                                   sizeof(values), 0U, 0U, 0U, 0};
    char output[OCRA_CHALLENGE_DIGITS + 1U];

    install_script(&script);
    require(ocra_generate_challenge(output) == 0,
            "maximum challenge value must generate");
    require(strcmp(output, "9999999999") == 0,
            "maximum challenge value must use ten nines");
    reset_provider();
}

static void test_leading_zeroes_are_preserved(void)
{
    static const uint64_t values[] = {UINT64_C(123456789)};
    struct random_script script = {(const unsigned char *)values,
                                   sizeof(values), 0U, 0U, 0U, 0};
    char output[OCRA_CHALLENGE_DIGITS + 1U];

    install_script(&script);
    require(ocra_generate_challenge(output) == 0,
            "a nine-digit numeric value must generate");
    require(strcmp(output, "0123456789") == 0,
            "a nine-digit value must retain its leading zero");
    reset_provider();
}

static void test_rejection_sampling_discards_values_at_the_limit(void)
{
    static const uint64_t values[] = {UINT64_C(18446744070000000000),
                                      UINT64_C(42)};
    struct random_script script = {(const unsigned char *)values,
                                   sizeof(values), 0U, 0U, 0U, 0};
    char output[OCRA_CHALLENGE_DIGITS + 1U];

    install_script(&script);
    require(ocra_generate_challenge(output) == 0,
            "a rejected sample followed by an accepted one must generate");
    require(strcmp(output, "0000000042") == 0,
            "the challenge must derive from the first accepted sample");
    require(script.offset == sizeof(values),
            "the boundary sample must be rejected before formatting");
    reset_provider();
}

static void test_multiple_interruptions_are_retried(void)
{
    static const uint64_t values[] = {UINT64_C(1)};
    struct random_script script = {(const unsigned char *)values,
                                   sizeof(values), 0U, 0U, 3U, 0};
    char output[OCRA_CHALLENGE_DIGITS + 1U];

    install_script(&script);
    require(ocra_generate_challenge(output) == 0,
            "multiple EINTR results must be retried");
    require(strcmp(output, "0000000001") == 0,
            "retried read must use the obtained random value");
    reset_provider();
}

static void test_permanent_random_source_failure_is_reported(void)
{
    struct random_script script = {NULL, 0U, 0U, 0U, 0U, 1};
    char output[OCRA_CHALLENGE_DIGITS + 1U];

    install_script(&script);
    require(ocra_generate_challenge(output) != 0,
            "permanent getrandom failure must not produce a challenge");
    reset_provider();
}

static void test_partial_reads_fill_one_complete_sample(void)
{
    static const uint64_t values[] = {UINT64_C(3141592653)};
    struct random_script script = {(const unsigned char *)values,
                                   sizeof(values), 0U, 3U, 0U, 0};
    char output[OCRA_CHALLENGE_DIGITS + 1U];

    install_script(&script);
    require(ocra_generate_challenge(output) == 0,
            "partial reads must be assembled into a complete sample");
    require(strcmp(output, "3141592653") == 0,
            "partial reads must not lose sample bytes");
    require(script.offset == sizeof(values),
            "partial reads must consume exactly one complete sample");
    reset_provider();
}

static void test_null_output_fails(void)
{
    require(ocra_generate_challenge(NULL) != 0, "NULL output must fail");
}

static void test_output_is_nul_terminated_without_overflow(void)
{
    static const uint64_t values[] = {UINT64_C(7)};
    struct random_script script = {(const unsigned char *)values,
                                   sizeof(values), 0U, 0U, 0U, 0};
    char guarded[OCRA_CHALLENGE_DIGITS + 3U];
    char *output = guarded + 1U;

    memset(guarded, 0xa5, sizeof(guarded));
    guarded[0] = 'L';
    guarded[sizeof(guarded) - 1U] = 'R';
    install_script(&script);
    require(ocra_generate_challenge(output) == 0,
            "a guarded output buffer must generate");
    require(output[OCRA_CHALLENGE_DIGITS] == '\0',
            "challenge must include a NUL terminator");
    require(guarded[0] == 'L' && guarded[sizeof(guarded) - 1U] == 'R',
            "challenge generation must not write outside its buffer");
    reset_provider();
}

static void test_test_provider_makes_generation_deterministic(void)
{
    static const uint64_t values[] = {UINT64_C(9876543210),
                                      UINT64_C(1234567890)};
    struct random_script script = {(const unsigned char *)values,
                                   sizeof(values), 0U, 0U, 0U, 0};
    char first[OCRA_CHALLENGE_DIGITS + 1U];
    char second[OCRA_CHALLENGE_DIGITS + 1U];

    install_script(&script);
    require(ocra_generate_challenge(first) == 0,
            "first scripted generation must succeed");
    require(ocra_generate_challenge(second) == 0,
            "second scripted generation must succeed");
    require(strcmp(first, "9876543210") == 0,
            "test provider must control the first challenge");
    require(strcmp(second, "1234567890") == 0,
            "test provider must control the second challenge");
    reset_provider();
}

int main(void)
{
    test_minimum_value_preserves_all_zeroes();
    test_maximum_challenge_value_is_representable();
    test_leading_zeroes_are_preserved();
    test_rejection_sampling_discards_values_at_the_limit();
    test_multiple_interruptions_are_retried();
    test_permanent_random_source_failure_is_reported();
    test_partial_reads_fill_one_complete_sample();
    test_null_output_fails();
    test_output_is_nul_terminated_without_overflow();
    test_test_provider_makes_generation_deterministic();
    return EXIT_SUCCESS;
}
