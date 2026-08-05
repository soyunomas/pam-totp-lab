#include "ocra_suite.h"

#include <stdint.h>
#include <string.h>

int ocra_suite_build_data_input(const char *challenge, size_t challenge_length,
                                unsigned char *output, size_t output_size)
{
    uint64_t question = 0U;
    uint64_t remaining;
    size_t index;
    size_t encoded_length = 0U;
    size_t question_offset = OCRA_SUITE_LENGTH + 1U;

    if (challenge == NULL || output == NULL || challenge_length != 10U ||
        output_size < OCRA_DATA_INPUT_BYTES) {
        return -1;
    }

    for (index = 0U; index < challenge_length; ++index) {
        unsigned char character = (unsigned char)challenge[index];

        if (character < (unsigned char)'0' || character > (unsigned char)'9') {
            return -1;
        }
        question = (question * UINT64_C(10)) +
                   (uint64_t)(character - (unsigned char)'0');
    }

    memset(output, 0, OCRA_DATA_INPUT_BYTES);
    memcpy(output, OCRA_SUITE, OCRA_SUITE_LENGTH);

    remaining = question;
    do {
        ++encoded_length;
        remaining >>= 8U;
    } while (remaining != 0U);

    for (index = 0U; index < encoded_length; ++index) {
        output[question_offset + encoded_length - 1U - index] =
            (unsigned char)(question & UINT64_C(0xff));
        question >>= 8U;
    }

    return 0;
}
