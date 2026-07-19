#include "../scope.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void check(int condition, const char *name)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

int main(void)
{
    const unsigned char secret_a[] = {1U, 2U, 3U, 4U};
    const unsigned char secret_b[] = {1U, 2U, 3U, 5U};
    char first[PTR_REPLAY_TAG_CAPACITY];
    char same[PTR_REPLAY_TAG_CAPACITY];
    char other_service[PTR_REPLAY_TAG_CAPACITY];
    char other_secret[PTR_REPLAY_TAG_CAPACITY];

    check(ptr_validate_service("sshd") == 0, "sshd service accepted");
    check(ptr_validate_service("login.local-1") == 0,
          "closed service alphabet accepted");
    check(ptr_validate_service("../sshd") != 0, "path traversal rejected");
    check(ptr_validate_service("") != 0, "empty service rejected");
    check(ptr_make_replay_tag("sshd", secret_a, sizeof(secret_a), first) == 0,
          "first tag generated");
    check(ptr_make_replay_tag("sshd", secret_a, sizeof(secret_a), same) == 0,
          "same tag generated");
    check(ptr_make_replay_tag("sudo", secret_a, sizeof(secret_a),
                              other_service) == 0,
          "service tag generated");
    check(ptr_make_replay_tag("sshd", secret_b, sizeof(secret_b),
                              other_secret) == 0,
          "secret tag generated");
    check(strcmp(first, same) == 0, "same scope stable");
    check(strcmp(first, other_service) != 0, "services isolated");
    check(strcmp(first, other_secret) != 0, "secret rotation isolated");
    check(strlen(first) < PTR_REPLAY_TAG_CAPACITY, "tag bounded");
    check(ptr_make_replay_tag("../bad", secret_a, sizeof(secret_a), first) != 0,
          "invalid service tag rejected");

    if (failures != 0) return EXIT_FAILURE;
    puts("rollover scope tests passed");
    return EXIT_SUCCESS;
}
