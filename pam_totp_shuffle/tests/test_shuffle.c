#include "../shuffle.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static int next_permutation(unsigned int values[PTS_CODE_LENGTH])
{
    size_t i = PTS_CODE_LENGTH - 1U;
    size_t j;

    while (i > 0U && values[i - 1U] >= values[i]) i--;
    if (i == 0U) return 0;
    j = PTS_CODE_LENGTH - 1U;
    while (values[j] <= values[i - 1U]) j--;
    {
        unsigned int temporary = values[i - 1U];
        values[i - 1U] = values[j];
        values[j] = temporary;
    }
    j = PTS_CODE_LENGTH - 1U;
    while (i < j) {
        unsigned int temporary = values[i];
        values[i] = values[j];
        values[j] = temporary;
        i++;
        j--;
    }
    return 1;
}

int main(void)
{
    unsigned int order[PTS_CODE_LENGTH] = {1U, 2U, 3U, 4U, 5U, 6U};
    const char original[] = "123456";
    size_t permutations = 0U;

    do {
        char transformed[PTS_CODE_LENGTH + 1U] = {0};
        char restored[PTS_CODE_LENGTH + 1U] = {0};
        char prompt[PTS_PROMPT_MAX];

        assert(pts_validate_permutation(order) == 0);
        for (size_t i = 0U; i < PTS_CODE_LENGTH; i++) {
            transformed[i] = original[order[i] - 1U];
        }
        assert(pts_restore_code(transformed, PTS_CODE_LENGTH, order, restored) == 0);
        assert(strcmp(restored, original) == 0);
        assert(pts_format_prompt(order, prompt, sizeof(prompt)) == 0);
        assert(strstr(prompt, "TOTP en orden ") == prompt);
        permutations++;
    } while (next_permutation(order));
    assert(permutations == 720U);

    {
        unsigned int duplicate[PTS_CODE_LENGTH] = {1U, 2U, 3U, 4U, 5U, 5U};
        unsigned int low[PTS_CODE_LENGTH] = {0U, 2U, 3U, 4U, 5U, 6U};
        unsigned int high[PTS_CODE_LENGTH] = {1U, 2U, 3U, 4U, 5U, 7U};
        char restored[PTS_CODE_LENGTH + 1U];
        assert(pts_validate_permutation(duplicate) != 0);
        assert(pts_validate_permutation(low) != 0);
        assert(pts_validate_permutation(high) != 0);
        assert(pts_restore_code("12345", 5U, order, restored) != 0);
        assert(pts_restore_code("12345x", 6U, order, restored) != 0);
    }

    for (size_t i = 0U; i < 2000U; i++) {
        assert(pts_generate_permutation(order) == 0);
        assert(pts_validate_permutation(order) == 0);
    }

    puts("test_shuffle: OK");
    return 0;
}
