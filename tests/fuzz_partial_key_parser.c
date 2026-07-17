#include "../pam_partial_key/keyfile.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct pk_key_data parsed;
    (void)pk_parse_key_data(data, size, &parsed);
    pk_key_data_clear(&parsed);
    return 0;
}
