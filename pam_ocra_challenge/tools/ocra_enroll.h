#ifndef OCRA_ENROLL_H
#define OCRA_ENROLL_H

enum ocra_enroll_fault_operation {
    OCRA_ENROLL_FAULT_NONE = 0,
    OCRA_ENROLL_FAULT_WRITE_PARTIAL,
    OCRA_ENROLL_FAULT_FSYNC_FILE,
    OCRA_ENROLL_FAULT_RENAME,
    OCRA_ENROLL_FAULT_FSYNC_DIRECTORY,
    OCRA_ENROLL_FAULT_RATE_CLEANUP,
    OCRA_ENROLL_FAULT_INTERRUPT_AFTER_CLIENT,
    OCRA_ENROLL_FAULT_INTERRUPT_AFTER_COMMITTING,
    OCRA_ENROLL_FAULT_INTERRUPT_AFTER_ADD_SERVER,
    OCRA_ENROLL_FAULT_INTERRUPT_REVOKE,
    OCRA_ENROLL_FAULT_INTERRUPT_PREPARE,
    OCRA_ENROLL_FAULT_INTERRUPT_RECOVERY
};

#ifdef OCRA_TESTING
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

typedef int (*ocra_enroll_random_provider)(void *buffer, size_t length);
typedef int (*ocra_enroll_user_provider)(const char *name, uid_t *uid,
                                         gid_t *gid);

int ocra_enroll_run_at_for_tests(int argc, char *const argv[], FILE *input,
                                 FILE *output, FILE *error,
                                 int server_root_fd, int rate_root_fd);
void ocra_enroll_set_random_provider_for_tests(
    ocra_enroll_random_provider provider);
void ocra_enroll_set_user_provider_for_tests(ocra_enroll_user_provider provider);
void ocra_enroll_set_euid_for_tests(uid_t euid);
void ocra_enroll_set_fault_for_tests(enum ocra_enroll_fault_operation operation,
                                     unsigned int occurrence);
void ocra_enroll_reset_test_providers(void);
#endif

#endif
