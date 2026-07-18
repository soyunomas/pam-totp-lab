#ifndef PAM_PARTIAL_KEY_KEYFILE_H
#define PAM_PARTIAL_KEY_KEYFILE_H

#include <stddef.h>

#define PK_SALT_LEN 16U
#define PK_HASH_LEN 32U
#define PK_MIN_PASS_LEN 8U
#define PK_MAX_PASS_LEN 64U
#define PK_MAX_FILE_SIZE 4224U

struct pk_key_data {
    size_t pass_len;
    unsigned char salt[PK_SALT_LEN];
    unsigned char hashes[PK_MAX_PASS_LEN][PK_HASH_LEN];
};

int pk_parse_key_data(const unsigned char *input, size_t input_len,
                      struct pk_key_data *data_out);
int pk_hash_position(unsigned char output[PK_HASH_LEN],
                     const unsigned char salt[PK_SALT_LEN], int index,
                     char character);
void pk_key_data_clear(struct pk_key_data *data);

#endif
