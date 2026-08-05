#include "challenge.h"

#include <errno.h>
#include <stdint.h>
#include <sys/random.h>

#define OCRA_CHALLENGE_RANGE UINT64_C(10000000000)
#define OCRA_RANDOM_ACCEPT_LIMIT UINT64_C(18446744070000000000)

static ssize_t ocra_system_getrandom(void *buffer, size_t length, int flags)
{
    return getrandom(buffer, length, flags);
}

#ifdef OCRA_TESTING
static ocra_challenge_random_provider random_provider = ocra_system_getrandom;

void ocra_challenge_set_random_provider_for_tests(
    ocra_challenge_random_provider provider)
{
    random_provider = provider;
}

void ocra_challenge_reset_random_provider_for_tests(void)
{
    random_provider = ocra_system_getrandom;
}
#endif

static ssize_t ocra_read_random(void *buffer, size_t length)
{
#ifdef OCRA_TESTING
    return random_provider(buffer, length, 0);
#else
    return ocra_system_getrandom(buffer, length, 0);
#endif
}

static int ocra_read_sample(uint64_t *sample)
{
    unsigned char *bytes = (unsigned char *)sample;
    size_t offset = 0U;

    while (offset < sizeof(*sample)) {
        ssize_t read_count = ocra_read_random(bytes + offset,
                                              sizeof(*sample) - offset);

        if (read_count > 0) {
            if ((size_t)read_count > sizeof(*sample) - offset) {
                return -1;
            }
            offset += (size_t)read_count;
            continue;
        }
        if (read_count < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}

int ocra_generate_challenge(char output[OCRA_CHALLENGE_DIGITS + 1U])
{
    uint64_t sample;
    size_t index;

    if (output == NULL) {
        return -1;
    }

    do {
        if (ocra_read_sample(&sample) != 0) {
            return -1;
        }
    } while (sample >= OCRA_RANDOM_ACCEPT_LIMIT);

    sample %= OCRA_CHALLENGE_RANGE;
    for (index = OCRA_CHALLENGE_DIGITS; index > 0U; --index) {
        output[index - 1U] =
            (char)('0' + (char)(sample % UINT64_C(10)));
        sample /= UINT64_C(10);
    }
    output[OCRA_CHALLENGE_DIGITS] = '\0';
    return 0;
}
