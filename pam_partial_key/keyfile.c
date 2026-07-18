#include "keyfile.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

int pk_hash_position(unsigned char output[PK_HASH_LEN],
                     const unsigned char salt[PK_SALT_LEN], int index,
                     char character)
{
    EVP_MD_CTX *context = NULL;
    unsigned int digest_length = 0U;
    int result = -1;

    if (output == NULL || salt == NULL || index < 0 ||
        index >= (int)PK_MAX_PASS_LEN) {
        return -1;
    }
    memset(output, 0, PK_HASH_LEN);
    context = EVP_MD_CTX_new();
    if (context != NULL &&
        EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(context, salt, PK_SALT_LEN) == 1 &&
        EVP_DigestUpdate(context, &index, sizeof(index)) == 1 &&
        EVP_DigestUpdate(context, &character, 1U) == 1 &&
        EVP_DigestFinal_ex(context, output, &digest_length) == 1 &&
        digest_length == PK_HASH_LEN) {
        result = 0;
    }
    EVP_MD_CTX_free(context);
    if (result != 0) memset(output, 0, PK_HASH_LEN);
    return result;
}

void pk_key_data_clear(struct pk_key_data *data)
{
    if (data == NULL) {
        return;
    }

    volatile unsigned char *bytes = (volatile unsigned char *)data;
    size_t remaining = sizeof(*data);
    while (remaining > 0U) {
        *bytes++ = 0U;
        remaining--;
    }
}

static int hex_value(unsigned char value)
{
    if (value >= (unsigned char)'0' && value <= (unsigned char)'9') {
        return (int)(value - (unsigned char)'0');
    }
    if (value >= (unsigned char)'a' && value <= (unsigned char)'f') {
        return (int)(value - (unsigned char)'a') + 10;
    }
    if (value >= (unsigned char)'A' && value <= (unsigned char)'F') {
        return (int)(value - (unsigned char)'A') + 10;
    }
    return -1;
}

static int decode_hex(const char *field, size_t field_len,
                      unsigned char *output, size_t output_len)
{
    if (field == NULL || output == NULL || field_len != output_len * 2U) {
        return -1;
    }

    for (size_t i = 0U; i < output_len; i++) {
        int high = hex_value((unsigned char)field[i * 2U]);
        int low = hex_value((unsigned char)field[(i * 2U) + 1U]);
        if (high < 0 || low < 0) {
            return -1;
        }
        output[i] = (unsigned char)(((unsigned int)high << 4U) |
                                    (unsigned int)low);
    }

    return 0;
}

static int parse_length(const char *field, size_t *length_out)
{
    size_t value = 0U;

    if (field == NULL || length_out == NULL || field[0] == '\0') {
        return -1;
    }

    for (size_t i = 0U; field[i] != '\0'; i++) {
        unsigned char digit = (unsigned char)field[i];
        if (digit < (unsigned char)'0' || digit > (unsigned char)'9') {
            return -1;
        }
        digit = (unsigned char)(digit - (unsigned char)'0');
        if (value > (PK_MAX_PASS_LEN - (size_t)digit) / 10U) {
            return -1;
        }
        value = (value * 10U) + (size_t)digit;
    }

    if (value < PK_MIN_PASS_LEN || value > PK_MAX_PASS_LEN) {
        return -1;
    }

    *length_out = value;
    return 0;
}

static char *take_delimited_field(char **cursor)
{
    char *field;
    char *delimiter;

    if (cursor == NULL || *cursor == NULL) {
        return NULL;
    }

    field = *cursor;
    delimiter = strchr(field, '|');
    if (delimiter == NULL) {
        return NULL;
    }

    *delimiter = '\0';
    *cursor = delimiter + 1;
    return field;
}

int pk_parse_key_data(const unsigned char *input, size_t input_len,
                      struct pk_key_data *data_out)
{
    struct pk_key_data candidate;
    size_t allocated_len = input_len;
    char *copy = NULL;
    char *cursor;
    char *field;
    int result = -1;

    if (data_out == NULL) {
        return -1;
    }
    pk_key_data_clear(data_out);
    pk_key_data_clear(&candidate);

    if (input == NULL || input_len == 0U || input_len > PK_MAX_FILE_SIZE ||
        memchr(input, '\0', input_len) != NULL) {
        return -1;
    }

    copy = malloc(input_len + 1U);
    if (copy == NULL) {
        return -1;
    }
    memcpy(copy, input, input_len);
    copy[input_len] = '\0';

    while (input_len > 0U &&
           (copy[input_len - 1U] == '\n' || copy[input_len - 1U] == '\r')) {
        copy[input_len - 1U] = '\0';
        input_len--;
    }
    if (input_len == 0U) {
        goto cleanup;
    }

    cursor = copy;
    field = take_delimited_field(&cursor);
    if (field == NULL || parse_length(field, &candidate.pass_len) != 0) {
        goto cleanup;
    }

    field = take_delimited_field(&cursor);
    if (field == NULL ||
        decode_hex(field, strlen(field), candidate.salt, PK_SALT_LEN) != 0) {
        goto cleanup;
    }

    for (size_t i = 0U; i < candidate.pass_len; i++) {
        if (i + 1U < candidate.pass_len) {
            field = take_delimited_field(&cursor);
            if (field == NULL) {
                goto cleanup;
            }
        } else {
            field = cursor;
            if (field == NULL || strchr(field, '|') != NULL) {
                goto cleanup;
            }
        }

        if (decode_hex(field, strlen(field), candidate.hashes[i],
                       PK_HASH_LEN) != 0) {
            goto cleanup;
        }
    }

    *data_out = candidate;
    result = 0;

cleanup:
    if (copy != NULL) {
        volatile unsigned char *bytes = (volatile unsigned char *)copy;
        for (size_t i = 0U; i < allocated_len + 1U; i++) {
            bytes[i] = 0U;
        }
        free(copy);
    }
    pk_key_data_clear(&candidate);
    if (result != 0) {
        pk_key_data_clear(data_out);
    }
    return result;
}
