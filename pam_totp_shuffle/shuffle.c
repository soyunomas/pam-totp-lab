#define _GNU_SOURCE

#include "shuffle.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>

static int pts_random_u32(uint32_t *value_out)
{
    unsigned char *cursor;
    size_t remaining;

    if (value_out == NULL) return -1;
    cursor = (unsigned char *)value_out;
    remaining = sizeof(*value_out);

    while (remaining > 0U) {
        ssize_t count = getrandom(cursor, remaining, 0U);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (count == 0) return -1;
        cursor += (size_t)count;
        remaining -= (size_t)count;
    }
    return 0;
}

static int pts_random_bounded(uint32_t bound, uint32_t *value_out)
{
    uint32_t random_value;
    uint32_t threshold;

    if (bound == 0U || value_out == NULL) return -1;
    threshold = (uint32_t)(0U - bound) % bound;

    do {
        if (pts_random_u32(&random_value) != 0) return -1;
    } while (random_value < threshold);

    *value_out = random_value % bound;
    return 0;
}

int pts_validate_permutation(const unsigned int order[PTS_CODE_LENGTH])
{
    unsigned int seen = 0U;

    if (order == NULL) return -1;
    for (size_t i = 0U; i < PTS_CODE_LENGTH; i++) {
        unsigned int position = order[i];
        unsigned int bit;

        if (position < 1U || position > PTS_CODE_LENGTH) return -1;
        bit = 1U << (position - 1U);
        if ((seen & bit) != 0U) return -1;
        seen |= bit;
    }
    return seen == ((1U << PTS_CODE_LENGTH) - 1U) ? 0 : -1;
}

int pts_generate_permutation(unsigned int order[PTS_CODE_LENGTH])
{
    if (order == NULL) return -1;
    for (size_t i = 0U; i < PTS_CODE_LENGTH; i++) order[i] = (unsigned int)i + 1U;

    for (size_t i = PTS_CODE_LENGTH - 1U; i > 0U; i--) {
        uint32_t selected;
        unsigned int temporary;

        if (pts_random_bounded((uint32_t)i + 1U, &selected) != 0) return -1;
        temporary = order[i];
        order[i] = order[selected];
        order[selected] = temporary;
    }
    return 0;
}

int pts_restore_code(const char *transformed, size_t transformed_length,
                     const unsigned int order[PTS_CODE_LENGTH],
                     char original[PTS_CODE_LENGTH + 1U])
{
    if (transformed == NULL || original == NULL ||
        transformed_length != PTS_CODE_LENGTH ||
        pts_validate_permutation(order) != 0) {
        return -1;
    }

    memset(original, 0, PTS_CODE_LENGTH + 1U);
    for (size_t i = 0U; i < PTS_CODE_LENGTH; i++) {
        unsigned char digit = (unsigned char)transformed[i];
        if (digit < (unsigned char)'0' || digit > (unsigned char)'9') {
            memset(original, 0, PTS_CODE_LENGTH + 1U);
            return -1;
        }
        original[order[i] - 1U] = (char)digit;
    }
    original[PTS_CODE_LENGTH] = '\0';
    return 0;
}

int pts_format_prompt(const unsigned int order[PTS_CODE_LENGTH], char *buffer,
                      size_t buffer_size)
{
    int written;

    if (buffer == NULL || buffer_size == 0U ||
        pts_validate_permutation(order) != 0) {
        return -1;
    }

    written = snprintf(buffer, buffer_size,
                       "TOTP en orden %u-%u-%u-%u-%u-%u: ", order[0], order[1],
                       order[2], order[3], order[4], order[5]);
    return written >= 0 && (size_t)written < buffer_size ? 0 : -1;
}
