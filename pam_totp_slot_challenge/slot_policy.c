#define _GNU_SOURCE

#include "slot_policy.h"

#include <errno.h>
#include <sys/random.h>

static const struct ptsc_slot slots[PTSC_MAX_SLOTS] = {
    {'A', "A.secret", "A", "pam_totp_slot_a"},
    {'B', "B.secret", "B", "pam_totp_slot_b"},
    {'C', "C.secret", "C", "pam_totp_slot_c"},
    {'D', "D.secret", "D", "pam_totp_slot_d"},
};

int ptsc_validate_slot_count(size_t slot_count)
{
    return slot_count >= PTSC_MIN_SLOTS && slot_count <= PTSC_MAX_SLOTS ? 0 : -1;
}

const struct ptsc_slot *ptsc_slot_by_index(size_t index)
{
    return index < PTSC_MAX_SLOTS ? &slots[index] : NULL;
}

int ptsc_select_index(size_t slot_count, ptsc_random_u32_fn random_u32,
                      void *context, size_t *index_out)
{
    uint32_t bound;
    uint32_t threshold;

    if (ptsc_validate_slot_count(slot_count) != 0 || random_u32 == NULL ||
        index_out == NULL) {
        return -1;
    }

    bound = (uint32_t)slot_count;
    threshold = (uint32_t)(0U - bound) % bound;

    for (;;) {
        uint32_t value = 0U;

        if (random_u32(&value, context) != 0) {
            return -1;
        }
        if (value >= threshold) {
            *index_out = (size_t)(value % bound);
            return 0;
        }
    }
}

static int system_random_u32(uint32_t *value_out, void *context)
{
    unsigned char *cursor;
    size_t remaining;

    (void)context;
    if (value_out == NULL) {
        return -1;
    }

    cursor = (unsigned char *)value_out;
    remaining = sizeof(*value_out);
    while (remaining > 0U) {
        ssize_t count = getrandom(cursor, remaining, 0U);

        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (count == 0) {
            return -1;
        }
        cursor += (size_t)count;
        remaining -= (size_t)count;
    }
    return 0;
}

int ptsc_random_index(size_t slot_count, size_t *index_out)
{
    return ptsc_select_index(slot_count, system_random_u32, NULL, index_out);
}
