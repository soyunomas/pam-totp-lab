#ifndef PAM_TOTP_SLOT_CHALLENGE_SLOT_POLICY_H
#define PAM_TOTP_SLOT_CHALLENGE_SLOT_POLICY_H

#include <stddef.h>
#include <stdint.h>

#define PTSC_MIN_SLOTS 2U
#define PTSC_MAX_SLOTS 4U

struct ptsc_slot {
    char id;
    const char *secret_file;
    const char *prompt_label;
    const char *replay_tag;
};

typedef int (*ptsc_random_u32_fn)(uint32_t *value_out, void *context);

int ptsc_validate_slot_count(size_t slot_count);
const struct ptsc_slot *ptsc_slot_by_index(size_t index);
int ptsc_select_index(size_t slot_count, ptsc_random_u32_fn random_u32,
                      void *context, size_t *index_out);
int ptsc_random_index(size_t slot_count, size_t *index_out);

#endif
