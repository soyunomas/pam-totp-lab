#include <errno.h>
#include <limits.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct conversation_data {
    const char **responses;
    size_t response_count;
    size_t next_response;
};

static void free_responses(struct pam_response *responses, int count)
{
    if (responses == NULL) {
        return;
    }

    for (int i = 0; i < count; i++) {
        free(responses[i].resp);
    }
    free(responses);
}

static int scripted_conversation(int num_msg,
                                 const struct pam_message **messages,
                                 struct pam_response **responses_out,
                                 void *appdata_ptr)
{
    struct conversation_data *data = appdata_ptr;
    struct pam_response *responses = NULL;

    if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG || messages == NULL ||
        responses_out == NULL || data == NULL) {
        return PAM_CONV_ERR;
    }

    responses = calloc((size_t)num_msg, sizeof(*responses));
    if (responses == NULL) {
        return PAM_BUF_ERR;
    }

    for (int i = 0; i < num_msg; i++) {
        if (messages[i] == NULL || messages[i]->msg == NULL) {
            free_responses(responses, num_msg);
            return PAM_CONV_ERR;
        }

        switch (messages[i]->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
        case PAM_PROMPT_ECHO_ON:
            if (data->next_response >= data->response_count) {
                free_responses(responses, num_msg);
                return PAM_CONV_ERR;
            }
            if (strlen(data->responses[data->next_response]) >=
                PAM_MAX_RESP_SIZE) {
                free_responses(responses, num_msg);
                return PAM_CONV_ERR;
            }
            responses[i].resp = strdup(data->responses[data->next_response]);
            if (responses[i].resp == NULL) {
                free_responses(responses, num_msg);
                return PAM_BUF_ERR;
            }
            data->next_response++;
            break;
        case PAM_ERROR_MSG:
        case PAM_TEXT_INFO:
            break;
        default:
            free_responses(responses, num_msg);
            return PAM_CONV_ERR;
        }
    }

    *responses_out = responses;
    return PAM_SUCCESS;
}

static int parse_status(const char *name, int *status_out)
{
    static const struct {
        const char *name;
        int status;
    } statuses[] = {
        {"success", PAM_SUCCESS},
        {"auth_err", PAM_AUTH_ERR},
        {"perm_denied", PAM_PERM_DENIED},
        {"service_err", PAM_SERVICE_ERR},
        {"system_err", PAM_SYSTEM_ERR},
        {"conv_err", PAM_CONV_ERR},
        {"ignore", PAM_IGNORE},
    };

    if (name == NULL || status_out == NULL) {
        return -1;
    }

    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++) {
        if (strcmp(name, statuses[i].name) == 0) {
            *status_out = statuses[i].status;
            return 0;
        }
    }

    errno = 0;
    char *end = NULL;
    long value = strtol(name, &end, 10);
    if (errno != 0 || end == name || *end != '\0' || value < 0 ||
        value > INT_MAX) {
        return -1;
    }

    *status_out = (int)value;
    return 0;
}

int main(int argc, char **argv)
{
    pam_handle_t *pamh = NULL;
    struct conversation_data data = {0};
    struct pam_conv conversation = {
        .conv = scripted_conversation,
        .appdata_ptr = &data,
    };
    int expected = PAM_SYSTEM_ERR;
    int result;
    int end_result;

    if (argc < 5) {
        fprintf(stderr,
                "usage: %s CONF_DIR SERVICE USER EXPECTED_STATUS [RESPONSE ...]\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    if (parse_status(argv[4], &expected) != 0) {
        fprintf(stderr, "invalid expected PAM status: %s\n", argv[4]);
        return EXIT_FAILURE;
    }

    data.responses = (const char **)&argv[5];
    data.response_count = (size_t)(argc - 5);

    result = pam_start_confdir(argv[2], argv[3], &conversation, argv[1],
                               &pamh);
    if (result != PAM_SUCCESS) {
        fprintf(stdout, "pam_start_confdir=%d, expected=%d\n", result,
                expected);
        return result == expected ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    result = pam_authenticate(pamh, 0);

    fprintf(stdout, "pam_authenticate=%d (%s), expected=%d\n", result,
            pam_strerror(pamh, result), expected);

    if (pamh == NULL) {
        return result == expected ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    end_result = pam_end(pamh, result);
    if (end_result != PAM_SUCCESS) {
        fprintf(stderr, "pam_end failed with status %d\n", end_result);
        return EXIT_FAILURE;
    }

    return result == expected ? EXIT_SUCCESS : EXIT_FAILURE;
}
