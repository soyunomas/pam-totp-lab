#ifndef PAM_MODULES_H
#define PAM_MODULES_H
#include <stddef.h>
typedef struct pam_handle pam_handle_t;
#define PAM_EXTERN
#define PAM_SUCCESS 0
#define PAM_OPEN_ERR 1
#define PAM_SYMBOL_ERR 2
#define PAM_SERVICE_ERR 3
#define PAM_SYSTEM_ERR 4
#define PAM_BUF_ERR 5
#define PAM_CONV_ERR 6
#define PAM_PERM_DENIED 7
#define PAM_AUTH_ERR 9
#define PAM_IGNORE 25
#define PAM_PROMPT_ECHO_OFF 1
#define PAM_SERVICE 1
#define PAM_MAX_RESP_SIZE 512
int pam_get_item(const pam_handle_t *, int, const void **);
int pam_get_user(pam_handle_t *, const char **, const char *);
int pam_set_data(pam_handle_t *, const char *, void *, void (*)(pam_handle_t *, void *, int));
int pam_get_data(const pam_handle_t *, const char *, const void **);
#endif
