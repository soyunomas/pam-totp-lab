#ifndef PSO_SCHEDULE_H
#define PSO_SCHEDULE_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define PSO_MAX_RULES 64U
#define PSO_MAX_USER_LEN 64U
#define PSO_MAX_SECRET_NAME_LEN 64U
#define PSO_MAX_CONFIG_SIZE 16384U

#define PSO_DEFAULT_DENY 0
#define PSO_DEFAULT_IGNORE 1

#define PSO_SCHEDULE_ERROR (-1)
#define PSO_SCHEDULE_OUTSIDE 0
#define PSO_SCHEDULE_INSIDE 1
#define PSO_SCHEDULE_UNMANAGED_DENY 2
#define PSO_SCHEDULE_UNMANAGED_IGNORE 3

struct pso_rule {
    char user[PSO_MAX_USER_LEN + 1U];
    char secret_name[PSO_MAX_SECRET_NAME_LEN + 1U];
    uint8_t days_mask;
    uint16_t start_minute;
    uint16_t end_minute;
};

struct pso_config {
    int default_policy;
    size_t rule_count;
    struct pso_rule rules[PSO_MAX_RULES];
};

void pso_secure_memzero(void *buffer, size_t length);
int pso_validate_username(const char *username);
int pso_validate_secret_name(const char *name);
int pso_validate_authorizer_name(const char *name);
int pso_parse_config(const char *text, size_t length, struct pso_config *out);
int pso_parse_authorizer_config(const char *text, size_t length,
                                struct pso_config *out);
int pso_evaluate_schedule(const struct pso_config *config, const char *username,
                          const struct tm *local_time,
                          const struct pso_rule **rule_out);

#endif
