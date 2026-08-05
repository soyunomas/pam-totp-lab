#include "../ocra_suite.h"
#include "../secure_memory.h"
#include "../ocra_core.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require(int condition, const char *message)
{
    if (!condition) {
        (void)fprintf(stderr, "test failure: %s\n", message);
        exit(EXIT_FAILURE);
    }
}

static void require_data_input(const char *challenge,
                               const unsigned char *question_prefix,
                               size_t question_prefix_length)
{
    static const char expected_suite[] = "OCRA-1:HOTP-SHA256-8:QN10";
    unsigned char data_input[154U];
    size_t question_offset = 26U;
    size_t index;

    memset(data_input, 0xa5, sizeof(data_input));
    require(ocra_suite_build_data_input(challenge, 10U, data_input,
                                        sizeof(data_input)) == 0,
            "valid challenge must serialize");
    require(memcmp(data_input, expected_suite, sizeof(expected_suite) - 1U) ==
                0,
            "data input must begin with the fixed suite");
    require(data_input[25U] == 0U,
            "suite must be followed by a NUL separator");
    require(memcmp(data_input + question_offset, question_prefix,
                   question_prefix_length) == 0,
            "question must use minimal big-endian encoding");
    for (index = question_offset + question_prefix_length;
         index < sizeof(data_input); ++index) {
        require(data_input[index] == 0U,
                "question padding and absent optional inputs must be zero");
    }
}

static void test_data_input_serialization(void)
{
    static const unsigned char question_1234567890[] = {0x49U, 0x96U, 0x02U,
                                                         0xd2U};
    static const unsigned char question_0123456789[] = {0x07U, 0x5bU, 0xcdU,
                                                         0x15U};
    static const unsigned char question_0000000000[] = {0x00U};
    static const unsigned char question_9999999999[] = {0x02U, 0x54U, 0x0bU,
                                                         0xe3U, 0xffU};

    require_data_input("1234567890", question_1234567890,
                       sizeof(question_1234567890));
    require_data_input("0123456789", question_0123456789,
                       sizeof(question_0123456789));
    require_data_input("0000000000", question_0000000000,
                       sizeof(question_0000000000));
    require_data_input("9999999999", question_9999999999,
                       sizeof(question_9999999999));
}

static void test_data_input_rejects_invalid_arguments(void)
{
    unsigned char data_input[154U];
    static const char embedded_nul[] = {'1', '2', '3', '4', '5', '\0', '7',
                                        '8', '9', '0'};

    require(ocra_suite_build_data_input(NULL, 10U, data_input, 154U) != 0,
            "NULL challenge must fail");
    require(ocra_suite_build_data_input("1234567890", 10U, NULL,
                                        154U) != 0,
            "NULL output must fail");
    require(ocra_suite_build_data_input("123456789", 9U, data_input,
                                        154U) != 0,
            "nine-digit challenge must fail");
    require(ocra_suite_build_data_input("12345678901", 11U, data_input,
                                        154U) != 0,
            "eleven-digit challenge must fail");
    require(ocra_suite_build_data_input("1234567890", 10U, data_input,
                                        153U) != 0,
            "short output buffer must fail");
    require(ocra_suite_build_data_input("123456789 ", 10U, data_input,
                                        154U) != 0,
            "space must fail");
    require(ocra_suite_build_data_input("123456789+", 10U, data_input,
                                        154U) != 0,
            "plus sign must fail");
    require(ocra_suite_build_data_input("123456789-", 10U, data_input,
                                        154U) != 0,
            "minus sign must fail");
    require(ocra_suite_build_data_input("123456789a", 10U, data_input,
                                        154U) != 0,
            "alphabetic byte must fail");
    require(ocra_suite_build_data_input(embedded_nul, sizeof(embedded_nul),
                                        data_input, 154U) != 0,
            "embedded NUL must fail");
}

static void test_secure_memory_clear_zeros_stack_buffer(void)
{
    unsigned char buffer[64];
    size_t index;

    memset(buffer, 0xa5, sizeof(buffer));
    secure_memory_clear(buffer, sizeof(buffer));
    for (index = 0U; index < sizeof(buffer); ++index) {
        require(buffer[index] == 0U, "secure clear must zero every byte");
    }
}

static void require_response_is_cleared(const char *response, size_t length,
                                        const char *message)
{
    size_t index;

    for (index = 0U; index < length; ++index) {
        require(response[index] == '\0', message);
    }
}

static void require_compute_error_clears_response(
    const unsigned char *secret, size_t secret_length, const char *challenge,
    size_t challenge_length, size_t response_size, const char *message)
{
    char response[16U];

    memset(response, 0xa5, sizeof(response));
    require(ocra_compute_response(secret, secret_length, challenge,
                                  challenge_length, response, response_size) !=
                0,
            message);
    require_response_is_cleared(response, response_size,
                                "error must clear every supplied response byte");
}

static void test_compute_rejects_invalid_arguments_and_clears_output(void)
{
    static const unsigned char secret[] = "12345678901234567890123456789012";
    static const char embedded_nul[] = {'1', '2', '3', '4', '5', '\0', '7',
                                        '8', '9', '0'};
    char short_response[8U];

    require_compute_error_clears_response(NULL, OCRA_SECRET_BYTES,
                                          "1234567890", 10U, 16U,
                                          "NULL secret must fail");
    require_compute_error_clears_response(secret, 31U, "1234567890", 10U,
                                          16U, "31-byte secret must fail");
    require_compute_error_clears_response(secret, 33U, "1234567890", 10U,
                                          16U, "33-byte secret must fail");
    require_compute_error_clears_response(secret, OCRA_SECRET_BYTES, NULL,
                                          10U, 16U,
                                          "NULL challenge must fail");
    require_compute_error_clears_response(secret, OCRA_SECRET_BYTES,
                                          "123456789", 9U, 16U,
                                          "nine-digit challenge must fail");
    require_compute_error_clears_response(secret, OCRA_SECRET_BYTES,
                                          "12345678901", 11U, 16U,
                                          "eleven-digit challenge must fail");
    require_compute_error_clears_response(secret, OCRA_SECRET_BYTES,
                                          "123456789 ", 10U, 16U,
                                          "space challenge must fail");
    require_compute_error_clears_response(secret, OCRA_SECRET_BYTES,
                                          "123456789+", 10U, 16U,
                                          "plus challenge must fail");
    require_compute_error_clears_response(secret, OCRA_SECRET_BYTES,
                                          "123456789-", 10U, 16U,
                                          "minus challenge must fail");
    require_compute_error_clears_response(secret, OCRA_SECRET_BYTES,
                                          "123456789a", 10U, 16U,
                                          "alphabetic challenge must fail");
    require_compute_error_clears_response(secret, OCRA_SECRET_BYTES,
                                          embedded_nul, sizeof(embedded_nul),
                                          16U,
                                          "embedded NUL challenge must fail");

    memset(short_response, 0xa5, sizeof(short_response));
    require(ocra_compute_response(secret, OCRA_SECRET_BYTES, "1234567890",
                                  10U, short_response,
                                  sizeof(short_response)) != 0,
            "response capacity eight must fail");
    require_response_is_cleared(short_response, sizeof(short_response),
                                "short response buffer must be cleared");
    require(ocra_compute_response(secret, OCRA_SECRET_BYTES, "1234567890",
                                  10U, NULL, OCRA_RESPONSE_CAPACITY) != 0,
            "NULL response must fail");
}

static void test_compute_response_format_and_determinism(void)
{
    static const unsigned char secret[] = "12345678901234567890123456789012";
    char first[16U];
    char second[OCRA_RESPONSE_CAPACITY];
    size_t index;

    memset(first, 0xa5, sizeof(first));
    require(ocra_compute_response(secret, OCRA_SECRET_BYTES, "0000000001",
                                  10U, first, sizeof(first)) == 0,
            "valid challenge must compute");
    require(strcmp(first, "06510410") == 0,
            "leading-zero response must be preserved");
    require(first[OCRA_RESPONSE_DIGITS] == '\0',
            "response must terminate after eight digits");
    for (index = 0U; index < OCRA_RESPONSE_DIGITS; ++index) {
        require(first[index] >= '0' && first[index] <= '9',
                "response must contain only decimal digits");
    }
    for (index = OCRA_RESPONSE_CAPACITY; index < sizeof(first); ++index) {
        require(first[index] == '\0',
                "successful call must retain cleared response tail");
    }

    require(ocra_compute_response(secret, OCRA_SECRET_BYTES, "0000000001",
                                  10U, second, sizeof(second)) == 0,
            "repeat call must compute");
    require(strcmp(first, second) == 0,
            "same inputs must produce a deterministic response");
}

static void test_compute_response_changes_when_secret_or_challenge_changes(void)
{
    static const unsigned char secret[] = "12345678901234567890123456789012";
    unsigned char changed_secret[OCRA_SECRET_BYTES];
    char baseline[OCRA_RESPONSE_CAPACITY];
    char changed[OCRA_RESPONSE_CAPACITY];

    memcpy(changed_secret, secret, sizeof(changed_secret));
    changed_secret[0] ^= 0x01U;
    require(ocra_compute_response(secret, OCRA_SECRET_BYTES, "1234567890",
                                  10U, baseline, sizeof(baseline)) == 0,
            "baseline response must compute");
    require(ocra_compute_response(changed_secret, sizeof(changed_secret),
                                  "1234567890", 10U, changed,
                                  sizeof(changed)) == 0,
            "one-bit secret mutation must compute");
    require(strcmp(baseline, changed) != 0,
            "one-bit secret mutation must change response");
    require(ocra_compute_response(secret, OCRA_SECRET_BYTES, "1234567891",
                                  10U, changed, sizeof(changed)) == 0,
            "one-digit challenge mutation must compute");
    require(strcmp(baseline, changed) != 0,
            "one-digit challenge mutation must change response");
}

int main(void)
{
    test_data_input_serialization();
    test_data_input_rejects_invalid_arguments();
    test_secure_memory_clear_zeros_stack_buffer();
    test_compute_rejects_invalid_arguments_and_clears_output();
    test_compute_response_format_and_determinism();
    test_compute_response_changes_when_secret_or_challenge_changes();
    return EXIT_SUCCESS;
}
