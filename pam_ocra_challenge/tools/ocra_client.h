#ifndef OCRA_CLIENT_H
#define OCRA_CLIENT_H

#ifdef OCRA_TESTING
#include <stdio.h>
#include <sys/stat.h>

typedef int (*ocra_client_stat_provider)(int fd, struct stat *status);

int ocra_client_run_for_tests(int argc, char *const argv[], FILE *input,
                              FILE *output, FILE *error, int config_fd);
void ocra_client_set_stat_provider_for_tests(ocra_client_stat_provider provider);
void ocra_client_reset_stat_provider_for_tests(void);
#endif

#endif
