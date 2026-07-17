#include "../pam_partial_key/keyfile.h"

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

static size_t build_valid(unsigned char *buffer, size_t capacity,
                          size_t pass_len, int newline)
{
    size_t used;
    int written = snprintf((char *)buffer, capacity, "%zu|", pass_len);
    if (written < 0 || (size_t)written >= capacity) {
        return 0U;
    }
    used = (size_t)written;

    for (size_t i = 0U; i < PK_SALT_LEN; i++) {
        written = snprintf((char *)buffer + used, capacity - used, "%02x",
                           (unsigned int)i);
        if (written != 2) {
            return 0U;
        }
        used += 2U;
    }

    if (used + 1U >= capacity) {
        return 0U;
    }
    buffer[used++] = (unsigned char)'|';

    for (size_t index = 0U; index < pass_len; index++) {
        for (size_t i = 0U; i < PK_HASH_LEN; i++) {
            written = snprintf((char *)buffer + used, capacity - used,
                               "%02x", (unsigned int)((index + i) & 0xffU));
            if (written != 2) {
                return 0U;
            }
            used += 2U;
        }
        if (index + 1U < pass_len) {
            if (used + 1U >= capacity) {
                return 0U;
            }
            buffer[used++] = (unsigned char)'|';
        }
    }

    if (newline) {
        if (used + 1U >= capacity) {
            return 0U;
        }
        buffer[used++] = (unsigned char)'\n';
    }
    buffer[used] = '\0';
    return used;
}

static void expect_invalid(const unsigned char *input, size_t input_len,
                           const char *name)
{
    struct pk_key_data data;
    memset(&data, 0xa5, sizeof(data));
    check(pk_parse_key_data(input, input_len, &data) != 0, name);

    const unsigned char *bytes = (const unsigned char *)&data;
    int cleared = 1;
    for (size_t i = 0U; i < sizeof(data); i++) {
        if (bytes[i] != 0U) {
            cleared = 0;
            break;
        }
    }
    check(cleared, "failure clears output");
}

int main(void)
{
    unsigned char buffer[PK_MAX_FILE_SIZE + 2U];
    unsigned char modified[PK_MAX_FILE_SIZE + 2U];
    struct pk_key_data data;
    size_t length;

    length = build_valid(buffer, sizeof(buffer), PK_MIN_PASS_LEN, 1);
    check(length > 0U, "build minimum fixture");
    check(pk_parse_key_data(buffer, length, &data) == 0,
          "parse minimum valid file");
    check(data.pass_len == PK_MIN_PASS_LEN, "minimum password length");
    check(data.salt[0] == 0U && data.salt[15] == 15U, "decode salt");
    check(data.hashes[1][2] == 3U, "decode positional hash");
    pk_key_data_clear(&data);

    length = build_valid(buffer, sizeof(buffer), PK_MAX_PASS_LEN, 1);
    check(length > 4095U && length <= PK_MAX_FILE_SIZE,
          "maximum fixture crosses old read limit");
    check(pk_parse_key_data(buffer, length, &data) == 0,
          "parse maximum valid file");
    check(data.pass_len == PK_MAX_PASS_LEN, "maximum password length");
    pk_key_data_clear(&data);

    length = build_valid(buffer, sizeof(buffer), PK_MIN_PASS_LEN, 0);
    check(pk_parse_key_data(buffer, length, &data) == 0,
          "newline is optional");
    pk_key_data_clear(&data);

    expect_invalid((const unsigned char *)"", 0U, "reject empty input");
    expect_invalid((const unsigned char *)"7|00|00", 7U,
                   "reject password shorter than policy");
    expect_invalid((const unsigned char *)"65|00|00", 8U,
                   "reject password longer than policy");
    expect_invalid((const unsigned char *)"+8|00|00", 8U,
                   "reject signed length");

    length = build_valid(buffer, sizeof(buffer), PK_MIN_PASS_LEN, 1);
    memcpy(modified, buffer, length + 1U);
    modified[3] = (unsigned char)'g';
    expect_invalid(modified, length, "reject non-hex salt");

    memcpy(modified, buffer, length + 1U);
    char *first_hash = strchr((char *)modified, '|');
    first_hash = first_hash == NULL ? NULL : strchr(first_hash + 1, '|');
    check(first_hash != NULL, "locate first hash");
    if (first_hash != NULL) {
        first_hash[1] = 'g';
        expect_invalid(modified, length, "reject non-hex hash");
    }

    memcpy(modified, buffer, length + 1U);
    modified[10] = '\0';
    expect_invalid(modified, length, "reject embedded NUL");

    memcpy(modified, buffer, length + 1U);
    char *last_separator = strrchr((char *)modified, '|');
    check(last_separator != NULL, "locate last separator");
    if (last_separator != NULL) {
        expect_invalid(modified, (size_t)(last_separator - (char *)modified),
                       "reject missing final hash");
    }

    memcpy(modified, buffer, length + 1U);
    modified[length - 1U] = (unsigned char)'|';
    modified[length++] = (unsigned char)'0';
    expect_invalid(modified, length, "reject extra field");

    memset(modified, '0', PK_MAX_FILE_SIZE + 1U);
    expect_invalid(modified, PK_MAX_FILE_SIZE + 1U, "reject oversized file");

    if (failures != 0) {
        fprintf(stderr, "%d parser test(s) failed\n", failures);
        return EXIT_FAILURE;
    }

    puts("All partial-key parser tests passed.");
    return EXIT_SUCCESS;
}
