#include "../pam_school_schedule/pam_school_schedule.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char maximum_a[MAX_TOKEN_LEN];
    char maximum_b[MAX_TOKEN_LEN];

    if (!secure_equals_const("token", "token")) {
        fputs("equal tokens rejected\n", stderr);
        return EXIT_FAILURE;
    }
    if (secure_equals_const("token", "token2") ||
        secure_equals_const("token", "tokeN")) {
        fputs("different tokens accepted\n", stderr);
        return EXIT_FAILURE;
    }

    memset(maximum_a, 'a', sizeof(maximum_a));
    memset(maximum_b, 'a', sizeof(maximum_b));
    maximum_a[MAX_TOKEN_LEN - 1U] = '\0';
    maximum_b[MAX_TOKEN_LEN - 1U] = '\0';
    if (!secure_equals_const(maximum_a, maximum_b)) {
        fputs("maximum valid token rejected\n", stderr);
        return EXIT_FAILURE;
    }

    memset(maximum_a, 'a', sizeof(maximum_a));
    memset(maximum_b, 'a', sizeof(maximum_b));
    if (secure_equals_const(maximum_a, maximum_b)) {
        fputs("unterminated token accepted\n", stderr);
        return EXIT_FAILURE;
    }

    puts("All school-schedule helper tests passed.");
    return EXIT_SUCCESS;
}
