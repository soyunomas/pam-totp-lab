#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdlib.h>
#include <string.h>

static int configured_result(int argc, const char **argv)
{
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "result=success") == 0) {
            return PAM_SUCCESS;
        }
        if (strcmp(argv[i], "result=ignore") == 0) {
            return PAM_IGNORE;
        }
        if (strcmp(argv[i], "result=auth_err") == 0) {
            return PAM_AUTH_ERR;
        }
        if (strcmp(argv[i], "result=service_err") == 0) {
            return PAM_SERVICE_ERR;
        }
    }

    return PAM_SERVICE_ERR;
}

static const char *argument_value(int argc, const char **argv,
                                  const char *prefix)
{
    size_t prefix_len = strlen(prefix);

    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], prefix, prefix_len) == 0) {
            return argv[i] + prefix_len;
        }
    }

    return NULL;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv)
{
    const char *expected_response;
    char *response = NULL;
    int result;

    (void)flags;

    result = configured_result(argc, argv);
    expected_response = argument_value(argc, argv, "expect=");
    if (expected_response == NULL) {
        return result;
    }

    if (pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &response,
                   "Test response: ") != PAM_SUCCESS ||
        response == NULL) {
        free(response);
        return PAM_CONV_ERR;
    }

    if (strcmp(response, expected_response) != 0) {
        result = PAM_AUTH_ERR;
    }

    memset(response, 0, strlen(response));
    free(response);
    return result;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
