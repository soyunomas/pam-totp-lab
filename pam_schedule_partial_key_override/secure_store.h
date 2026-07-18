#ifndef SPK_SECURE_STORE_H
#define SPK_SECURE_STORE_H

#include "../pam_partial_key/keyfile.h"
#include "../pam_schedule_totp_override/schedule.h"

#include <stddef.h>

#define SPK_STORE_ERROR (-1)
#define SPK_STORE_OK 0
#define SPK_CONFIG_FILE "pam-schedule-partial-key.conf"
#define SPK_KEY_DIRECTORY "pam-schedule-partial-key"

int spk_load_config(struct pso_config *config_out);
int spk_load_key(const char *authorizer, struct pk_key_data *key_out,
                 unsigned char key_id[32]);

#endif
