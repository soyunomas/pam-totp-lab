#include "../ocra_core.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ocra_vector {
    const char *challenge;
    const char *response;
};

static void require(int condition, const char *message)
{
    if (!condition) {
        (void)fprintf(stderr, "test failure: %s\n", message);
        exit(EXIT_FAILURE);
    }
}

static void test_fixed_suite_vectors(void)
{
    static const unsigned char secret[] = "12345678901234567890123456789012";
    static const struct ocra_vector vectors[] = {
        {"0000000000", "36899090"}, {"0000000001", "06510410"},
        {"0123456789", "51707911"}, {"1234567890", "75619513"},
        {"9999999999", "13786538"},
    };
    size_t index;

    for (index = 0U; index < sizeof(vectors) / sizeof(vectors[0]); ++index) {
        char response[OCRA_RESPONSE_CAPACITY];

        require(ocra_compute_response(secret, OCRA_SECRET_BYTES,
                                      vectors[index].challenge,
                                      OCRA_CHALLENGE_DIGITS, response,
                                      sizeof(response)) == 0,
                "fixed-suite vector must compute");
        require(strcmp(response, vectors[index].response) == 0,
                "fixed-suite response must match independent vector");
    }
}

int main(void)
{
    test_fixed_suite_vectors();
    return EXIT_SUCCESS;
}
