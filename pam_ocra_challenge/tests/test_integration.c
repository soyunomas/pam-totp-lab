#define _GNU_SOURCE

#include <fcntl.h>
#include <limits.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct conversation_state {
    const char *response;
    unsigned int information_count;
    unsigned int prompt_count;
    int cancel_prompt;
};

struct integration_fixture {
    char directory[sizeof("/tmp/ocra-pam-policy-XXXXXX")];
    char policy_path[PATH_MAX];
    struct conversation_state conversation_state;
    struct pam_conv conversation;
    pam_handle_t *handle;
    int last_result;
};

static void free_responses(struct pam_response *responses, int count)
{
    int index;

    if (responses == NULL) {
        return;
    }
    for (index = 0; index < count; ++index) {
        free(responses[index].resp);
    }
    free(responses);
}

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
            free_responses(responses, count);
            return PAM_CONV_ERR;
        }
        if (messages[index]->msg_style == PAM_TEXT_INFO) {
            state->information_count++;
        } else if (messages[index]->msg_style == PAM_PROMPT_ECHO_OFF) {
            state->prompt_count++;
            if (state->cancel_prompt != 0) {
                free_responses(responses, count);
                return PAM_CONV_ERR;
            }
            responses[index].resp = strdup(state->response);
            if (responses[index].resp == NULL) {
                free_responses(responses, count);
                return PAM_BUF_ERR;
            }
        } else {
            free_responses(responses, count);
            return PAM_CONV_ERR;
        }
    }
    *responses_out = responses;
    return PAM_SUCCESS;
}

static int write_policy(const char *directory, const char *module_path,
                        const char *control, char policy_path[PATH_MAX])
{
    char policy[PATH_MAX + 32U];
    int policy_length;
    int path_length;
    int fd;
    int result = -1;

    path_length = snprintf(policy_path, PATH_MAX, "%s/ocra-integration",
                           directory);
    policy_length = snprintf(policy, sizeof(policy), "auth %s %s\n", control,
                             module_path);
    if (path_length < 0 || path_length >= PATH_MAX || policy_length < 0 ||
        (size_t)policy_length >= sizeof(policy)) {
        return -1;
    }
    fd = open(policy_path,
              O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        return -1;
    }
    if (write(fd, policy, (size_t)policy_length) == policy_length &&
        close(fd) == 0) {
        fd = -1;
        result = 0;
    }
    if (fd >= 0) {
        (void)close(fd);
    }
    return result;
}

static int fixture_start(struct integration_fixture *fixture,
                         const char *module_path, const char *control)
{
    static const char directory_template[] =
        "/tmp/ocra-pam-policy-XXXXXX";

    (void)memset(fixture, 0, sizeof(*fixture));
    (void)memcpy(fixture->directory, directory_template,
                 sizeof(directory_template));
    fixture->conversation_state.response = "75619513";
    fixture->conversation.conv = scripted_conversation;
    fixture->conversation.appdata_ptr = &fixture->conversation_state;
    fixture->last_result = PAM_SYSTEM_ERR;
    if (mkdtemp(fixture->directory) == NULL ||
        write_policy(fixture->directory, module_path, control,
                     fixture->policy_path) != 0) {
        return -1;
    }
    fixture->last_result = pam_start_confdir(
        "ocra-integration", "isolated-user", &fixture->conversation,
        fixture->directory, &fixture->handle);
    return fixture->last_result == PAM_SUCCESS ? 0 : -1;
}

static int fixture_authenticate(struct integration_fixture *fixture,
                                const char *response, int cancel_prompt)
{
    fixture->conversation_state.response = response;
    fixture->conversation_state.cancel_prompt = cancel_prompt;
    fixture->last_result = pam_authenticate(fixture->handle, 0);
    return fixture->last_result;
}

static void fixture_destroy(struct integration_fixture *fixture)
{
    if (fixture->handle != NULL) {
        (void)pam_end(fixture->handle, fixture->last_result);
        fixture->handle = NULL;
    }
    if (fixture->policy_path[0] != '\0') {
        (void)unlink(fixture->policy_path);
    }
    if (fixture->directory[0] != '\0') {
        (void)rmdir(fixture->directory);
    }
}

static int test_required_flow_and_rate_limit(const char *module_path)
{
    struct integration_fixture fixture;
    unsigned int attempt;
    int result = -1;

    if (fixture_start(&fixture, module_path, "required") != 0) {
        fixture_destroy(&fixture);
        return -1;
    }
    if (fixture_authenticate(&fixture, "75619513", 0) != PAM_SUCCESS ||
        fixture.conversation_state.information_count != 1U ||
        fixture.conversation_state.prompt_count != 1U) {
        goto cleanup;
    }
    if (fixture_authenticate(&fixture, "75619513", 1) != PAM_AUTH_ERR ||
        fixture.conversation_state.information_count != 2U ||
        fixture.conversation_state.prompt_count != 2U) {
        goto cleanup;
    }
    if (fixture_authenticate(&fixture, "75619513", 0) != PAM_SUCCESS) {
        goto cleanup;
    }

    for (attempt = 0U; attempt < 6U; ++attempt) {
        unsigned int information_before =
            fixture.conversation_state.information_count;
        unsigned int prompts_before = fixture.conversation_state.prompt_count;

        if (fixture_authenticate(&fixture, "00000000", 0) != PAM_AUTH_ERR ||
            (attempt < 5U &&
             (fixture.conversation_state.information_count !=
                  information_before + 1U ||
              fixture.conversation_state.prompt_count !=
                  prompts_before + 1U)) ||
            (attempt == 5U &&
             (fixture.conversation_state.information_count !=
                  information_before ||
              fixture.conversation_state.prompt_count != prompts_before))) {
            goto cleanup;
        }
    }
    result = 0;

cleanup:
    if (result != 0) {
        (void)fprintf(stderr,
                      "required integration failure: pam=%d info=%u "
                      "prompt=%u\n",
                      fixture.last_result,
                      fixture.conversation_state.information_count,
                      fixture.conversation_state.prompt_count);
    }
    fixture_destroy(&fixture);
    return result;
}

static int test_requisite_success(const char *module_path)
{
    struct integration_fixture fixture;
    int result = -1;

    if (fixture_start(&fixture, module_path, "requisite") != 0) {
        fixture_destroy(&fixture);
        return -1;
    }
    if (fixture_authenticate(&fixture, "75619513", 0) == PAM_SUCCESS &&
        fixture.conversation_state.information_count == 1U &&
        fixture.conversation_state.prompt_count == 1U) {
        result = 0;
    } else {
        (void)fprintf(stderr,
                      "requisite integration failure: pam=%d info=%u "
                      "prompt=%u\n",
                      fixture.last_result,
                      fixture.conversation_state.information_count,
                      fixture.conversation_state.prompt_count);
    }
    fixture_destroy(&fixture);
    return result;
}

int main(void)
{
    const char *module_path = getenv("OCRA_MODULE_BIN");

    if (module_path == NULL || module_path[0] != '/' ||
        test_required_flow_and_rate_limit(module_path) != 0 ||
        test_requisite_success(module_path) != 0) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
