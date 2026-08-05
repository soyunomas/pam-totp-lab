#ifndef OCRA_SECRET_STORE_H
#define OCRA_SECRET_STORE_H

#include <stddef.h>
#include <sys/types.h>

#define OCRA_SECRET_BYTES 32U
#define OCRA_KEY_ID_HEX_LENGTH 16U
#define OCRA_SECRET_FILE_MAX 4096U
#define OCRA_SECRET_LINE_MAX 512U

struct ocra_secret_record {
    unsigned char secret[OCRA_SECRET_BYTES];
    char key_id[OCRA_KEY_ID_HEX_LENGTH + 1U];
};

void ocra_secret_record_clear(struct ocra_secret_record *record);
int ocra_secret_record_parse(const unsigned char *data, size_t length,
                             struct ocra_secret_record *record);
int ocra_secret_store_load(uid_t uid, const char *service,
                           struct ocra_secret_record *record);
int ocra_secret_store_load_at(int root_fd, const char *uid_text,
                              const char *service,
                              struct ocra_secret_record *record);

#ifdef OCRA_TESTING
#include <sys/stat.h>

typedef void (*ocra_secret_store_after_open_hook)(int file_fd, void *context);
typedef int (*ocra_secret_store_stat_provider)(int fd, struct stat *status);

int ocra_secret_store_parse_for_tests(const unsigned char *data, size_t length,
                                      struct ocra_secret_record *record);
void ocra_secret_store_set_after_open_hook_for_tests(
    ocra_secret_store_after_open_hook hook, void *context);
void ocra_secret_store_reset_after_open_hook_for_tests(void);
void ocra_secret_store_set_stat_provider_for_tests(
    ocra_secret_store_stat_provider provider);
void ocra_secret_store_reset_stat_provider_for_tests(void);
#endif

#endif
