#ifndef TEST_PAM_MODULES_H
#define TEST_PAM_MODULES_H

typedef struct pam_handle pam_handle_t;
#define PAM_EXTERN extern
#define PAM_SUCCESS 0
#define PAM_AUTH_ERR 7
#define PAM_SERVICE_ERR 3
#define PAM_PROMPT_ECHO_OFF 1
#define PAM_MAX_RESP_SIZE 512

int pam_get_user(pam_handle_t *, const char **, const char *);

#endif
