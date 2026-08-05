#ifndef OCRA_CORE_H
#define OCRA_CORE_H

#include <stddef.h>

#define OCRA_CHALLENGE_DIGITS 10U
#define OCRA_RESPONSE_DIGITS 8U
#define OCRA_SECRET_BYTES 32U
#define OCRA_RESPONSE_CAPACITY (OCRA_RESPONSE_DIGITS + 1U)

int ocra_compute_response(const unsigned char *secret, size_t secret_length,
                          const char *challenge, size_t challenge_length,
                          char *response, size_t response_size);

#endif
