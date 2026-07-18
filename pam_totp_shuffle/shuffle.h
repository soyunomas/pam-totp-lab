#ifndef PAM_TOTP_SHUFFLE_SHUFFLE_H
#define PAM_TOTP_SHUFFLE_SHUFFLE_H

#include <stddef.h>

#define PTS_CODE_LENGTH 6U
#define PTS_PROMPT_MAX 64U

int pts_validate_permutation(const unsigned int order[PTS_CODE_LENGTH]);
int pts_generate_permutation(unsigned int order[PTS_CODE_LENGTH]);
int pts_restore_code(const char *transformed, size_t transformed_length,
                     const unsigned int order[PTS_CODE_LENGTH],
                     char original[PTS_CODE_LENGTH + 1U]);
int pts_format_prompt(const unsigned int order[PTS_CODE_LENGTH], char *buffer,
                      size_t buffer_size);

#endif
