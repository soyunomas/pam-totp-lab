#include "../slot_policy.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct scripted_rng {
    const uint32_t *values;
    size_t count;
    size_t position;
    int fail;
};

static int scripted_random(uint32_t *value_out, void *context)
{
    struct scripted_rng *rng = context;

    if (rng == NULL || value_out == NULL || rng->fail != 0 ||
        rng->position >= rng->count) {
        return -1;
    }
    *value_out = rng->values[rng->position++];
    return 0;
}

static void test_policy(void)
{
    static const char ids[] = {'A', 'B', 'C', 'D'};
    static const char *const files[] = {
        "A.secret", "B.secret", "C.secret", "D.secret"
    };

    assert(ptsc_validate_slot_count(1U) != 0);
    assert(ptsc_validate_slot_count(2U) == 0);
    assert(ptsc_validate_slot_count(3U) == 0);
    assert(ptsc_validate_slot_count(4U) == 0);
    assert(ptsc_validate_slot_count(5U) != 0);

    for (size_t i = 0U; i < PTSC_MAX_SLOTS; i++) {
        const struct ptsc_slot *slot = ptsc_slot_by_index(i);

        assert(slot != NULL);
        assert(slot->id == ids[i]);
        assert(strcmp(slot->secret_file, files[i]) == 0);
        assert(slot->prompt_label[0] == ids[i]);
        assert(slot->prompt_label[1] == '\0');
        assert(strncmp(slot->replay_tag, "pam_totp_slot_", 14U) == 0);
    }
    assert(ptsc_slot_by_index(PTSC_MAX_SLOTS) == NULL);
}

static void test_unbiased_rejection(void)
{
    const uint32_t values[] = {0U, 5U};
    struct scripted_rng rng = {values, 2U, 0U, 0};
    size_t index = 99U;

    /* For bound 3, threshold is 1: zero must be rejected. */
    assert(ptsc_select_index(3U, scripted_random, &rng, &index) == 0);
    assert(rng.position == 2U);
    assert(index == 2U);
}

static void test_failures(void)
{
    const uint32_t values[] = {7U};
    struct scripted_rng rng = {values, 1U, 0U, 0};
    size_t index = 0U;

    assert(ptsc_select_index(1U, scripted_random, &rng, &index) != 0);
    assert(ptsc_select_index(5U, scripted_random, &rng, &index) != 0);
    assert(ptsc_select_index(2U, NULL, &rng, &index) != 0);
    assert(ptsc_select_index(2U, scripted_random, &rng, NULL) != 0);

    rng.fail = 1;
    assert(ptsc_select_index(2U, scripted_random, &rng, &index) != 0);
}

static void test_system_random(void)
{
    unsigned int seen[PTSC_MAX_SLOTS] = {0U};

    for (size_t i = 0U; i < 4096U; i++) {
        size_t index = PTSC_MAX_SLOTS;

        assert(ptsc_random_index(4U, &index) == 0);
        assert(index < 4U);
        seen[index]++;
    }
    for (size_t i = 0U; i < 4U; i++) {
        assert(seen[i] > 0U);
    }
}

int main(void)
{
    test_policy();
    test_unbiased_rejection();
    test_failures();
    test_system_random();
    puts("slot policy tests passed");
    return 0;
}
