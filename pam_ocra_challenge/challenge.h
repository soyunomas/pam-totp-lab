#ifndef OCRA_CHALLENGE_H
#define OCRA_CHALLENGE_H

#include "ocra_core.h"

#ifdef OCRA_TESTING
#include <stddef.h>
#include <sys/types.h>

typedef ssize_t (*ocra_challenge_random_provider)(void *buffer, size_t length,
                                                   int flags);

void ocra_challenge_set_random_provider_for_tests(
    ocra_challenge_random_provider provider);
void ocra_challenge_reset_random_provider_for_tests(void);
#endif

int ocra_generate_challenge(char output[OCRA_CHALLENGE_DIGITS + 1U]);

#endif
