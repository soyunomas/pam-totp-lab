#ifndef PSO_SECURE_STORE_H
#define PSO_SECURE_STORE_H

#include "schedule.h"

#include <stddef.h>
#include <sys/types.h>

#define PSO_SECURITY_DIRECTORY "/etc/security"
#define PSO_CONFIG_FILE "pam-schedule-override.conf"
#define PSO_SECRET_DIRECTORY "pam-schedule-override"
#define PSO_MAX_SECRET_LEN 128U
#define PSO_MIN_SECRET_LEN 16U

#define PSO_STORE_ERROR (-1)
#define PSO_STORE_OK 0
#define PSO_STORE_NOT_FOUND 1

int pso_validate_base32_secret(const char *secret, size_t length);
int pso_read_config_at(int security_dir_fd, uid_t expected_owner,
                       struct pso_config *config_out);
int pso_read_secret_at(int security_dir_fd, uid_t expected_owner,
                       const char *secret_name, char *secret_out,
                       size_t secret_capacity);
int pso_load_config(struct pso_config *config_out);
int pso_load_secret(const char *secret_name, char *secret_out,
                    size_t secret_capacity);

#endif
