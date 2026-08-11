#ifndef OCRA_TEST_PAM_EXT_H
#define OCRA_TEST_PAM_EXT_H

#include "pam_modules.h"

int pam_info(pam_handle_t *, const char *, ...);
int pam_prompt(pam_handle_t *, int, char **, const char *, ...);
int pam_fail_delay(pam_handle_t *, unsigned int);

#endif
