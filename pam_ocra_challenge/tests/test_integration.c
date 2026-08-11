#define _GNU_SOURCE

#include <fcntl.h>
#include <limits.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct conversation_state {
    unsigned int information_count;
    unsigned int prompt_count;
};

static int scripted_conversation(int count,
                                 const struct pam_message **messages,
                                 struct pam_response **responses_out,
                                 void *context)
{
    struct conversation_state *state = context;
    struct pam_response *responses;
    int index;

    if (count <= 0 || messages == NULL || responses_out == NULL ||
        state == NULL) {
        return PAM_CONV_ERR;
    }
    responses = calloc((size_t)count, sizeof(*responses));
    if (responses == NULL) {
        return PAM_BUF_ERR;
    }
    for (index = 0; index < count; ++index) {
        if (messages[index] == NULL || messages[index]->msg == NULL) {
            free(responses);
            return PAM_CONV_ERR;
        }
        if (messages[index]->msg_style == PAM_TEXT_INFO) {
            state->information_count++;
        } else if (messages[index]->msg_style == PAM_PROMPT_ECHO_OFF) {
            responses[index].resp = strdup("75619513");
            if (responses[index].resp == NULL) {
                free(responses);
                return PAM_BUF_ERR;
            }
            state->prompt_count++;
        } else {
            free(responses);
            return PAM_CONV_ERR;
        }
    }
    *responses_out = responses;
    return PAM_SUCCESS;
}

static int write_policy(const char *directory, const char *module_path,
                        char policy_path[PATH_MAX])
{
    char policy[PATH_MAX + 32U];
    int policy_length;
    int path_length;
    int fd;

    path_length = snprintf(policy_path, PATH_MAX, "%s/ocra-integration",
                           directory);
    policy_length = snprintf(policy, sizeof(policy), "auth required %s\n",
                             module_path);
    if (path_length < 0 || path_length >= PATH_MAX || policy_length < 0 ||
        (size_t)policy_length >= sizeof(policy)) {
        return -1;
    }
    fd = open(policy_path,
              O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0 || write(fd, policy, (size_t)policy_length) != policy_length ||
        close(fd) != 0) {
        if (fd >= 0) {
            (void)close(fd);
        }
        return -1;
    }
    return 0;
}

int main(void)
{
    const char *module_path = getenv("OCRA_MODULE_BIN");
    char directory[] = "/tmp/ocra-pam-policy-XXXXXX";
    char policy_path[PATH_MAX];
    struct conversation_state state = {0U, 0U};
    struct pam_conv conversation = {scripted_conversation, &state};
    pam_handle_t *handle = NULL;
    int result = PAM_SYSTEM_ERR;
    int exit_status = EXIT_FAILURE;

    (void)memset(policy_path, 0, sizeof(policy_path));
    if (module_path == NULL || module_path[0] != '/' ||
        mkdtemp(directory) == NULL ||
        write_policy(directory, module_path, policy_path) != 0) {
        goto cleanup;
    }
    result = pam_start_confdir("ocra-integration", "isolated-user",
                               &conversation, directory, &handle);
    if (result == PAM_SUCCESS) {
        result = pam_authenticate(handle, 0);
    }
    if (result == PAM_SUCCESS && state.information_count == 1U &&
        state.prompt_count == 1U) {
        exit_status = EXIT_SUCCESS;
    } else {
        (void)fprintf(stderr,
                      "integration failure: pam=%d info=%u prompt=%u\n",
                      result, state.information_count, state.prompt_count);
    }

cleanup:
    if (handle != NULL) {
        (void)pam_end(handle, result);
    }
    if (policy_path[0] != '\0') {
        (void)unlink(policy_path);
    }
    (void)rmdir(directory);
    return exit_status;
}
