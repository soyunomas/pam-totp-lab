#include "../secret_store.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_ITERATIONS 10000U

static const unsigned char valid_seed[] =
    "version=1\n"
    "suite=OCRA-1:HOTP-SHA256-8:QN10\n"
    "key_id=0123456789abcdef\n"
    "secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    "enabled=yes\n";

static void require(int condition, const char *message)
{
    if (!condition) {
        (void)fprintf(stderr, "fuzz failure: %s\n", message);
        exit(EXIT_FAILURE);
    }
}

static uint32_t next_random(uint32_t *state)
{
    uint32_t value = *state;

    value ^= value << 13U;
    value ^= value >> 17U;
    value ^= value << 5U;
    *state = value;
    return value;
}

static int memory_is_zero(const void *memory, size_t length)
{
    const unsigned char *bytes = memory;
    size_t index;

    for (index = 0U; index < length; ++index) {
        if (bytes[index] != 0U) {
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    unsigned char input[OCRA_SECRET_FILE_MAX + 1U];
    struct ocra_secret_record record;
    uint32_t state = UINT32_C(0x6f637261);
    size_t iteration;

    memset(&record, 0xa5, sizeof(record));
    require(ocra_secret_store_parse_for_tests(valid_seed,
                                              sizeof(valid_seed) - 1U,
                                              &record) == 0,
            "valid seed must exercise the accepting parser path");
    ocra_secret_record_clear(&record);

    for (iteration = 0U; iteration < FUZZ_ITERATIONS; ++iteration) {
        size_t length;
        size_t index;

        if ((iteration & 1U) == 0U) {
            size_t mutations = 1U + (next_random(&state) % 8U);

            length = sizeof(valid_seed) - 1U;
            memcpy(input, valid_seed, length);
            for (index = 0U; index < mutations; ++index) {
                size_t position = next_random(&state) % length;

                input[position] = (unsigned char)next_random(&state);
            }
        } else {
            length = next_random(&state) % sizeof(input);
            for (index = 0U; index < length; ++index) {
                input[index] = (unsigned char)next_random(&state);
            }
        }

        memset(&record, 0xa5, sizeof(record));
        if (ocra_secret_store_parse_for_tests(input, length, &record) != 0) {
            require(memory_is_zero(&record, sizeof(record)),
                    "every rejected fuzz input must clear output");
        }
        ocra_secret_record_clear(&record);
    }

    (void)printf("fuzz_secret_parser: %u deterministic inputs\n",
                 FUZZ_ITERATIONS);
    return EXIT_SUCCESS;
}
