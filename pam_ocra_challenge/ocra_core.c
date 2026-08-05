#include "ocra_core.h"

#include "ocra_suite.h"
#include "secure_memory.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <stdint.h>

int ocra_compute_response(const unsigned char *secret, size_t secret_length,
                          const char *challenge, size_t challenge_length,
                          char *response, size_t response_size)
{
    unsigned char data_input[OCRA_DATA_INPUT_BYTES];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned char *hmac_result;
    unsigned int digest_length = 0U;
    uint32_t truncated;
    uint32_t response_value;
    size_t index;
    size_t offset;
    int result = -1;

    if (response != NULL && response_size != 0U) {
        secure_memory_clear(response, response_size);
    }

    if (secret == NULL || secret_length != OCRA_SECRET_BYTES ||
        challenge == NULL || challenge_length != OCRA_CHALLENGE_DIGITS ||
        response == NULL || response_size < OCRA_RESPONSE_CAPACITY) {
        goto cleanup;
    }

    if (ocra_suite_build_data_input(challenge, challenge_length, data_input,
                                    sizeof(data_input)) != 0) {
        goto cleanup;
    }

    hmac_result = HMAC(EVP_sha256(), secret, (int)secret_length, data_input,
                       sizeof(data_input), digest, &digest_length);
    if (hmac_result == NULL || digest_length != 32U) {
        goto cleanup;
    }

    offset = (size_t)(digest[31U] & 0x0fU);
    truncated = ((uint32_t)digest[offset] << 24U) |
                ((uint32_t)digest[offset + 1U] << 16U) |
                ((uint32_t)digest[offset + 2U] << 8U) |
                (uint32_t)digest[offset + 3U];
    response_value = (truncated & UINT32_C(0x7fffffff)) % UINT32_C(100000000);

    for (index = OCRA_RESPONSE_DIGITS; index > 0U; --index) {
        response[index - 1U] =
            (char)('0' + (char)(response_value % UINT32_C(10)));
        response_value /= UINT32_C(10);
    }
    response[OCRA_RESPONSE_DIGITS] = '\0';
    result = 0;

cleanup:
    secure_memory_clear(data_input, sizeof(data_input));
    secure_memory_clear(digest, sizeof(digest));
    return result;
}
