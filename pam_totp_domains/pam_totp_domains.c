#define _GNU_SOURCE

#include "domains.h"
#include "secret_file.h"
#include "../pam_common/totp_replay.h"

#include <fcntl.h>
#include <grp.h>
#include <liboath/oath.h>
#include <pthread.h>
#include <pwd.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define PTD_TOTP_STEP 30U
#define PTD_TOTP_WINDOW 1U
#define PTD_FAIL_DELAY 3000000U
#define PTD_MAX_PASSWD_BUFFER (1024U * 1024U)
#define PTD_FAKE_SECRET "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

static pthread_once_t oath_once = PTHREAD_ONCE_INIT;
static int oath_init_status = OATH_CRYPTO_ERROR;

static void initialize_oath(void) { oath_init_status = oath_init(); }

static int ensure_oath_initialized(void)
{
    return pthread_once(&oath_once, initialize_oath) == 0 &&
                   oath_init_status == OATH_OK
               ? 0
               : -1;
}

static void secure_memzero(void *value, size_t length)
{
    if (value == NULL) return;
    volatile unsigned char *bytes = (volatile unsigned char *)value;
    while (length > 0U) {
        *bytes++ = 0U;
        length--;
    }
}

static void secure_free(void **value, size_t length)
{
    if (value != NULL && *value != NULL) {
        secure_memzero(*value, length);
        free(*value);
        *value = NULL;
    }
}

static int restore_privileges(uid_t uid, gid_t gid, int group_count,
                              const gid_t *groups)
{
    int failed = 0;
    if (seteuid(uid) != 0) failed = 1;
    if (setegid(gid) != 0) failed = 1;
    if (group_count > 0 && groups != NULL) {
        if (setgroups((size_t)group_count, groups) != 0) failed = 1;
    } else if (setgroups(0U, NULL) != 0) failed = 1;
    return failed ? -1 : 0;
}

static int parse_options(int argc, const char **argv, int *nullok_out)
{
    int nullok = 0;
    if (nullok_out == NULL) return -1;
    for (int i = 0; i < argc; i++) {
        if (argv[i] == NULL) return -1;
        if (strcmp(argv[i], "nullok") == 0) nullok = 1;
        else return -1;
    }
    *nullok_out = nullok;
    return 0;
}

static int load_user_secret(const char *username,
                            const struct ptd_domain *domain,
                            char secret_out[PTD_MAX_SECRET_LEN + 1U],
                            uid_t *uid_out)
{
    struct passwd pwd;
    struct passwd *pwd_result = NULL;
    char *pwd_buffer = NULL;
    gid_t *saved_groups = NULL;
    long configured_size;
    size_t pwd_buffer_size;
    uid_t saved_uid;
    gid_t saved_gid;
    int saved_group_count;
    int home_fd = -1;
    int result = PTD_SECRET_ERROR;

    if (username == NULL || domain == NULL || secret_out == NULL || uid_out == NULL)
        return PTD_SECRET_ERROR;
    memset(secret_out, 0, PTD_MAX_SECRET_LEN + 1U);
    memset(&pwd, 0, sizeof(pwd));

    configured_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (configured_size < 0) configured_size = 16384;
    if (configured_size <= 0 ||
        (unsigned long)configured_size > PTD_MAX_PASSWD_BUFFER)
        return PTD_SECRET_ERROR;
    pwd_buffer_size = (size_t)configured_size;
    pwd_buffer = calloc(1U, pwd_buffer_size);
    if (pwd_buffer == NULL) return PTD_SECRET_ERROR;

    if (getpwnam_r(username, &pwd, pwd_buffer, pwd_buffer_size, &pwd_result) != 0 ||
        pwd_result == NULL || pwd.pw_dir == NULL || pwd.pw_dir[0] != '/')
        goto cleanup;
    *uid_out = pwd.pw_uid;

    saved_uid = geteuid();
    saved_gid = getegid();
    saved_group_count = getgroups(0, NULL);
    if (saved_group_count < 0) goto cleanup;
    if (saved_group_count > 0) {
        if ((size_t)saved_group_count > SIZE_MAX / sizeof(gid_t)) goto cleanup;
        saved_groups = malloc((size_t)saved_group_count * sizeof(gid_t));
        if (saved_groups == NULL ||
            getgroups(saved_group_count, saved_groups) < 0) goto cleanup;
    }

    if (initgroups(username, pwd.pw_gid) != 0 || setegid(pwd.pw_gid) != 0 ||
        seteuid(pwd.pw_uid) != 0) {
        if (restore_privileges(saved_uid, saved_gid, saved_group_count,
                               saved_groups) != 0) abort();
        goto cleanup;
    }

    home_fd = open(pwd.pw_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (home_fd >= 0) {
        result = ptd_read_secret_at(home_fd, pwd.pw_uid, domain, secret_out,
                                    PTD_MAX_SECRET_LEN + 1U);
        close(home_fd);
        home_fd = -1;
    }

    if (restore_privileges(saved_uid, saved_gid, saved_group_count,
                           saved_groups) != 0) {
        syslog(LOG_CRIT, "PAM_TOTP_DOMAINS: could not restore credentials");
        abort();
    }

cleanup:
    if (home_fd >= 0) close(home_fd);
    if (pwd_buffer != NULL) {
        secure_memzero(pwd_buffer, pwd_buffer_size);
        free(pwd_buffer);
    }
    free(saved_groups);
    if (result != PTD_SECRET_OK)
        secure_memzero(secret_out, PTD_MAX_SECRET_LEN + 1U);
    return result;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv)
{
    const void *service_item = NULL;
    const char *service;
    const char *username = NULL;
    const struct ptd_domain *domain;
    char secret_base32[PTD_MAX_SECRET_LEN + 1U] = {0};
    char prompt[64] = {0};
    char *otp_input = NULL;
    char *secret_binary = NULL;
    size_t otp_length = 0U;
    size_t secret_binary_length = 0U;
    uid_t user_id = (uid_t)0;
    uint64_t counter = UINT64_C(0);
    int nullok = 0;
    int fake_mode = 0;
    int result = PAM_AUTH_ERR;

    (void)flags;
    if (pamh == NULL || geteuid() != (uid_t)0 ||
        parse_options(argc, argv, &nullok) != 0 ||
        pam_get_item(pamh, PAM_SERVICE, &service_item) != PAM_SUCCESS ||
        service_item == NULL) return PAM_SERVICE_ERR;

    service = (const char *)service_item;
    domain = ptd_domain_for_service(service);
    if (domain == NULL) return PAM_AUTH_ERR;
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || username == NULL ||
        ensure_oath_initialized() != 0) return PAM_AUTH_ERR;

    int secret_status = load_user_secret(username, domain, secret_base32, &user_id);
    if (secret_status == PTD_SECRET_NOT_FOUND && nullok) return PAM_IGNORE;
    if (secret_status != PTD_SECRET_OK) {
        fake_mode = 1;
        memcpy(secret_base32, PTD_FAKE_SECRET, sizeof(PTD_FAKE_SECRET));
    }

    int prompt_length = snprintf(prompt, sizeof(prompt), "TOTP [%s]: ", domain->label);
    if (prompt_length < 0 || (size_t)prompt_length >= sizeof(prompt)) goto cleanup;
    if (pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &otp_input, "%s", prompt) !=
            PAM_SUCCESS || otp_input == NULL) goto cleanup;

    otp_length = strnlen(otp_input, PAM_MAX_RESP_SIZE);
    if (otp_length == PAM_MAX_RESP_SIZE || otp_length < 6U || otp_length > 8U)
        goto cleanup;
    for (size_t i = 0U; i < otp_length; i++)
        if (otp_input[i] < '0' || otp_input[i] > '9') goto cleanup;

    int oath_result = oath_base32_decode(secret_base32, strlen(secret_base32),
                                         &secret_binary, &secret_binary_length);
    secure_memzero(secret_base32, sizeof(secret_base32));
    if (oath_result != OATH_OK) goto cleanup;

    time_t now = time(NULL);
    if (now == (time_t)-1) goto cleanup;
    oath_result = oath_totp_validate3(secret_binary, secret_binary_length, now,
                                      PTD_TOTP_STEP, 0, PTD_TOTP_WINDOW, NULL,
                                      &counter, otp_input);
    if (oath_result >= 0 && !fake_mode) {
        int replay = totp_replay_check_and_store(domain->replay_tag, user_id,
                                                 counter);
        if (replay == TOTP_REPLAY_ACCEPTED) result = PAM_SUCCESS;
        else syslog(replay == TOTP_REPLAY_DETECTED ? LOG_NOTICE : LOG_ERR,
                    "PAM_TOTP_DOMAINS: rejected counter for %s in %s",
                    username, domain->label);
    } else if (!fake_mode) {
        syslog(LOG_NOTICE, "PAM_TOTP_DOMAINS: invalid TOTP for %s in %s",
               username, domain->label);
    }

cleanup:
    secure_memzero(secret_base32, sizeof(secret_base32));
    secure_memzero(prompt, sizeof(prompt));
    if (secret_binary != NULL)
        secure_free((void **)&secret_binary, secret_binary_length);
    if (otp_input != NULL) {
        if (otp_length == 0U) otp_length = strnlen(otp_input, PAM_MAX_RESP_SIZE);
        secure_free((void **)&otp_input, otp_length);
    }
    if (result != PAM_SUCCESS) (void)pam_fail_delay(pamh, PTD_FAIL_DELAY);
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
