#include "../config.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>

int main(void)
{
    size_t count = 0U;
    const char *valid2[] = {"slots=2"};
    const char *valid3[] = {"slots=3"};
    const char *valid4[] = {"slots=4"};
    const char *low[] = {"slots=1"};
    const char *high[] = {"slots=5"};
    const char *long_value[] = {"slots=22"};
    const char *unknown[] = {"nullok"};
    const char *duplicate[] = {"slots=2", "slots=3"};

    assert(ptsc_parse_options(1, valid2, &count) == 0 && count == 2U);
    assert(ptsc_parse_options(1, valid3, &count) == 0 && count == 3U);
    assert(ptsc_parse_options(1, valid4, &count) == 0 && count == 4U);
    assert(ptsc_parse_options(0, NULL, &count) != 0);
    assert(ptsc_parse_options(1, low, &count) != 0);
    assert(ptsc_parse_options(1, high, &count) != 0);
    assert(ptsc_parse_options(1, long_value, &count) != 0);
    assert(ptsc_parse_options(1, unknown, &count) != 0);
    assert(ptsc_parse_options(2, duplicate, &count) != 0);
    assert(ptsc_parse_options(1, valid2, NULL) != 0);
    puts("config tests passed");
    return 0;
}
