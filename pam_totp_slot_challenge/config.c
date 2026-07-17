#include "config.h"
#include "slot_policy.h"

#include <string.h>

int ptsc_parse_options(int argc, const char *const argv[],
                       size_t *slot_count_out)
{
    const char prefix[] = "slots=";
    size_t slot_count;

    if (slot_count_out == NULL || argc != 1 || argv == NULL ||
        argv[0] == NULL || strncmp(argv[0], prefix, sizeof(prefix) - 1U) != 0 ||
        argv[0][sizeof(prefix) - 1U] == '\0' ||
        argv[0][sizeof(prefix)] != '\0') {
        return -1;
    }

    if (argv[0][sizeof(prefix) - 1U] < '0' ||
        argv[0][sizeof(prefix) - 1U] > '9') {
        return -1;
    }
    slot_count = (size_t)(argv[0][sizeof(prefix) - 1U] - '0');
    if (ptsc_validate_slot_count(slot_count) != 0) {
        return -1;
    }

    *slot_count_out = slot_count;
    return 0;
}
