#include "../pam_chronoguard/pam_chronoguard.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    const struct tm fixed_time = {
        .tm_min = 34,
        .tm_hour = 12,
        .tm_mday = 17,
        .tm_mon = 6,
        .tm_year = 126,
        .tm_wday = 5,
    };
    char output[64];
    char boundary[5];

    if (build_time_string("YYYY-YY-AA-MM-DD-HH-MI-WD", &fixed_time, output,
                          sizeof(output)) != 0 ||
        strcmp(output, "20262626071712345") != 0) {
        fprintf(stderr, "unexpected expanded time: %s\n", output);
        return EXIT_FAILURE;
    }

    if (build_time_string("YYYY", &fixed_time, boundary, sizeof(boundary)) != 0 ||
        strcmp(boundary, "2026") != 0) {
        fprintf(stderr, "unexpected boundary expansion: %s\n", boundary);
        return EXIT_FAILURE;
    }

    if (build_time_string("literal-only", &fixed_time, output,
                          sizeof(output)) == 0) {
        fputs("format without time tokens was accepted\n", stderr);
        return EXIT_FAILURE;
    }

    if (build_time_string("", &fixed_time, output, sizeof(output)) != 0 ||
        output[0] != '\0') {
        fputs("empty optional format was rejected\n", stderr);
        return EXIT_FAILURE;
    }

    puts("All chronoguard helper tests passed.");
    return EXIT_SUCCESS;
}
