/*
 * ==============================================================================
 *  PAM 2-MAN RULE TOTP - High Security Dual Control Module
 * ==============================================================================
 *
 *  Author:      Soyunomas
 *  Repository:  https://github.com/soyunomas/pam-totp-lab
 *  License:     MIT
 *  Standard:    MISRA-C / CERT C / OpenBSD Style
 *  Description: Enforces Two-Person Integrity (TPI) via TOTP.
 *               Requires Initiator + Privileged Authorizer (Wheel).
 *
 *  SECURITY FEATURES:
 *  [x] Fail-Close Default
 *  [x] Privilege Dropping (EUID/EGID)
 *  [x] TOCTOU Mitigation (fstat)
 *  [x] Memory Wiping (explicit_bzero fallback)
 *  [x] Constant Time Logic (Anti-Enumeration)
 *  [x] Input Whitelisting
 *
 * ==============================================================================
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <pthread.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <liboath/oath.h>

#include "../pam_common/totp_replay.h"

/* --- CONFIGURATION CONSTANTS --- */
#define SECRET_FILENAME     ".google_authenticator"
#define PRIVILEGED_GROUP    "wheel"
#define TOTP_WINDOW         1
#define TOTP_STEP           30
#define FAIL_DELAY_MS       3000000
#define MAX_USERNAME_LEN    255U
#define MAX_NSS_BUFFER      (1024U * 1024U)
#define FAKE_TOTP_SECRET    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

static pthread_once_t oath_once = PTHREAD_ONCE_INIT;
static int oath_init_status = OATH_CRYPTO_ERROR;

static void initialize_oath(void)
{
    /* Keep liboath initialized for the process lifetime to avoid teardown races. */
    oath_init_status = oath_init();
}

static int ensure_oath_initialized(void)
{
    return pthread_once(&oath_once, initialize_oath) == 0 &&
                   oath_init_status == OATH_OK
               ? 0
               : -1;
}

/* Internal Status Codes */
typedef enum {
    STATUS_OK = 0,
    STATUS_ERR_SYSTEM = -1,
    STATUS_ERR_AUTH = -2,
    STATUS_ERR_FILE = -3,
    STATUS_NOT_FOUND = -4  /* Explicitly for missing file */
} secure_status_t;

/* --- SECURITY UTILS --- */

static void secure_memzero(void *s, size_t n) {
    if (!s || n == 0) return;
#ifdef HAVE_EXPLICIT_BZERO
    explicit_bzero(s, n);
#else
    volatile unsigned char *p = (volatile unsigned char *)s;
    while (n--) *p++ = 0;
    __asm__ __volatile__("" : : "r"(s) : "memory");
#endif
}

static void secure_free(void **ptr, size_t size) {
    if (ptr && *ptr) {
        if (size > 0) secure_memzero(*ptr, size);
        free(*ptr);
        *ptr = NULL;
    }
}

static int restore_privileges(uid_t uid, gid_t gid, int group_count,
                               const gid_t *groups)
{
    int failed = 0;
    if (seteuid(uid) != 0) failed = 1;
    if (setegid(gid) != 0) failed = 1;
    if (group_count > 0 && groups != NULL) {
        if (setgroups(group_count, groups) != 0) failed = 1;
    } else if (setgroups(0, NULL) != 0) {
        failed = 1;
    }
    return failed ? -1 : 0;
}

static int safe_strcpy(char *dest, size_t size, const char *src) {
    int written;
    if (!dest || !src || size == 0) return -1;
    dest[0] = '\0';
    written = snprintf(dest, size, "%s", src);
    if (written < 0 || (size_t)written >= size) {
        return -1;
    }
    return 0;
}

static int initialize_fake_secret(char *secret_buf, size_t buf_size)
{
    if (secret_buf == NULL || buf_size == 0U) return -1;
    memset(secret_buf, 0, buf_size);
    return safe_strcpy(secret_buf, buf_size, FAKE_TOTP_SECRET);
}

/* --- CORE LOGIC --- */

static int is_user_privileged(const char *username, const char *groupname) {
    struct group group_entry;
    struct group *group_result = NULL;
    struct passwd password_entry;
    struct passwd *password_result = NULL;
    char *group_buffer = NULL;
    char *password_buffer = NULL;
    long configured_size;
    size_t group_buffer_size;
    size_t password_buffer_size;
    gid_t privileged_gid;
    int privileged = 0;

    if (!username || !groupname) return 0;

    configured_size = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (configured_size < 0) configured_size = 16384;
    if (configured_size <= 0 ||
        (unsigned long)configured_size > MAX_NSS_BUFFER) {
        return 0;
    }
    group_buffer_size = (size_t)configured_size;
    group_buffer = calloc(1U, group_buffer_size);
    if (group_buffer == NULL ||
        getgrnam_r(groupname, &group_entry, group_buffer, group_buffer_size,
                   &group_result) != 0 ||
        group_result == NULL) {
        syslog(LOG_ERR, "PAM_2MAN: Critical - Group %s not found.", groupname);
        goto cleanup;
    }
    privileged_gid = group_entry.gr_gid;

    if (group_entry.gr_mem != NULL) {
        for (char **member = group_entry.gr_mem; *member != NULL; member++) {
            if (strcmp(*member, username) == 0) {
                privileged = 1;
                goto cleanup;
            }
        }
    }

    configured_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (configured_size < 0) configured_size = 16384;
    if (configured_size <= 0 ||
        (unsigned long)configured_size > MAX_NSS_BUFFER) {
        goto cleanup;
    }
    password_buffer_size = (size_t)configured_size;
    password_buffer = calloc(1U, password_buffer_size);
    if (password_buffer != NULL &&
        getpwnam_r(username, &password_entry, password_buffer,
                   password_buffer_size, &password_result) == 0 &&
        password_result != NULL && password_entry.pw_gid == privileged_gid) {
        privileged = 1;
    }

cleanup:
    free(password_buffer);
    free(group_buffer);
    return privileged;
}

/*
 * Load Secret.
 * Returns STATUS_NOT_FOUND if file is missing (useful for nullok).
 * Returns STATUS_OK if loaded.
 * Returns error otherwise.
 */
static secure_status_t load_user_secret(const char *username, char *secret_buf,
                                        size_t buf_size, int *fake_mode_out,
                                        uid_t *uid_out) {
    secure_status_t status = STATUS_ERR_SYSTEM;
    struct passwd pwd;
    struct passwd *result = NULL;
    char *buf_pwd = NULL;
    char filepath[PATH_MAX];
    FILE *fp = NULL;
    int fd = -1;
    
    *fake_mode_out = 1;
    /* Pre-fill with valid fake data for constant time ops */
    if (initialize_fake_secret(secret_buf, buf_size) != 0) {
        return STATUS_ERR_SYSTEM;
    }

    long bufsize_sys = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize_sys == -1) bufsize_sys = 16384;

    buf_pwd = calloc(1, (size_t)bufsize_sys);
    if (!buf_pwd) return STATUS_ERR_SYSTEM;

    if (getpwnam_r(username, &pwd, buf_pwd, (size_t)bufsize_sys, &result) != 0 || result == NULL) {
        secure_free((void**)&buf_pwd, (size_t)bufsize_sys);
        return STATUS_ERR_AUTH; 
    }
    *uid_out = pwd.pw_uid;

    if (snprintf(filepath, sizeof(filepath), "%s/%s", pwd.pw_dir, SECRET_FILENAME) >= (int)sizeof(filepath)) {
        secure_free((void**)&buf_pwd, (size_t)bufsize_sys);
        return STATUS_ERR_SYSTEM;
    }

    /* Save Privs */
    uid_t root_uid = geteuid();
    gid_t root_gid = getegid();
    int ngroups = getgroups(0, NULL);
    gid_t *groups = NULL;
    if (ngroups < 0) {
        secure_free((void**)&buf_pwd, (size_t)bufsize_sys);
        return STATUS_ERR_SYSTEM;
    }
    if (ngroups > 0) {
        if ((size_t)ngroups > SIZE_MAX / sizeof(gid_t)) {
            secure_free((void**)&buf_pwd, (size_t)bufsize_sys);
            return STATUS_ERR_SYSTEM;
        }
        groups = malloc((size_t)ngroups * sizeof(gid_t));
        if (!groups) {
             secure_free((void**)&buf_pwd, (size_t)bufsize_sys);
             return STATUS_ERR_SYSTEM;
        }
        if (getgroups(ngroups, groups) == -1) {
            free(groups);
            secure_free((void**)&buf_pwd, (size_t)bufsize_sys);
            return STATUS_ERR_SYSTEM;
        }
    }

    /* DROP PRIVILEGES */
    if (initgroups(username, pwd.pw_gid) != 0 || 
        setegid(pwd.pw_gid) != 0 || 
        seteuid(pwd.pw_uid) != 0) {
        if (restore_privileges(root_uid, root_gid, ngroups, groups) != 0) {
            abort();
        }
        secure_free((void**)&buf_pwd, (size_t)bufsize_sys);
        if (groups) free(groups);
        return STATUS_ERR_SYSTEM;
    }

    /* Open File */
    fd = open(filepath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    
    if (fd == -1) {
        if (errno == ENOENT) status = STATUS_NOT_FOUND;
        else status = STATUS_ERR_FILE;
    } else {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            if (S_ISREG(st.st_mode) && st.st_uid == pwd.pw_uid && (st.st_mode & 0077) == 0) {
                fp = fdopen(fd, "r");
                if (fp) {
                    if (fgets(secret_buf, (int)buf_size, fp) != NULL) {
                        size_t len = strnlen(secret_buf, buf_size);
                        while(len > 0 && (secret_buf[len-1] == '\n' || secret_buf[len-1] == '\r' || secret_buf[len-1] == ' ')) {
                            secret_buf[len-1] = '\0';
                            len--;
                        }
                        if (len >= 16) {
                            *fake_mode_out = 0;
                            status = STATUS_OK;
                        } else {
                            status = STATUS_ERR_FILE; /* Invalid content */
                        }
                    }
                    fclose(fp);
                } else {
                    close(fd);
                }
            } else {
                syslog(LOG_WARNING, "PAM_2MAN: Bad permissions on %s", filepath);
                close(fd);
                status = STATUS_ERR_FILE;
            }
        } else {
            close(fd);
        }
    }

    /* RESTORE PRIVILEGES */
    if (restore_privileges(root_uid, root_gid, ngroups, groups) != 0) abort();

    if (groups) free(groups);
    secure_free((void**)&buf_pwd, (size_t)bufsize_sys);

    return status;
}

static int verify_totp(const char *username, const char *secret_base32,
                       const char *input_code, int fake_mode,
                       uint64_t *counter_out) {
    char *secret_bin = NULL;
    size_t secret_bin_len = 0;
    int rc;

    if (counter_out == NULL) return PAM_AUTH_ERR;
    *counter_out = UINT64_C(0);

    size_t input_len = strnlen(input_code, 9U);
    if (input_len < 6U || input_len > 8U) return PAM_AUTH_ERR;
    for (size_t i = 0; i < input_len; i++) {
        if (input_code[i] < '0' || input_code[i] > '9') return PAM_AUTH_ERR;
    }

    rc = oath_base32_decode(secret_base32, strlen(secret_base32), &secret_bin, &secret_bin_len);
    if (rc != OATH_OK) {
        if (!fake_mode) syslog(LOG_ERR, "PAM_2MAN: Bad Base32 for %s", username);
        return PAM_AUTH_ERR;
    }

    time_t now = time(NULL);
    if (now == (time_t)-1) {
        secure_free((void**)&secret_bin, secret_bin_len);
        return PAM_AUTH_ERR;
    }
    rc = oath_totp_validate3(secret_bin, secret_bin_len, now, TOTP_STEP, 0,
                             TOTP_WINDOW, NULL, counter_out, input_code);
    secure_free((void**)&secret_bin, secret_bin_len);

    if (rc >= 0 && !fake_mode) return PAM_SUCCESS;
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags;
    
    const char *user1 = NULL;
    char *user2_input = NULL;
    char *otp1 = NULL;
    char *otp2 = NULL;
    
    char secret1[256];
    char secret2[256];
    int fake1 = 1, fake2 = 1;
    uid_t user1_id = (uid_t)0;
    uid_t user2_id = (uid_t)0;
    uint64_t counter1 = UINT64_C(0);
    uint64_t counter2 = UINT64_C(0);
    int ret;
    int final_result = PAM_AUTH_ERR;
    int nullok = 0;
    size_t otp1_len = 0U;
    size_t otp2_len = 0U;
    size_t user2_len = 0U;
    secure_status_t status1;

    /* Parse Arguments */
    for (int i = 0; i < argc; i++) {
        if (argv[i] && strcmp(argv[i], "nullok") == 0) {
            nullok = 1;
        }
    }

    memset(secret1, 0, sizeof(secret1));
    if (initialize_fake_secret(secret2, sizeof(secret2)) != 0) {
        return PAM_AUTH_ERR;
    }

    /* --- FASE 1: INICIADOR (User 1) --- */
    if (pam_get_user(pamh, &user1, NULL) != PAM_SUCCESS || user1 == NULL) {
        return PAM_AUTH_ERR;
    }
    if (ensure_oath_initialized() != 0) {
        return PAM_AUTH_ERR;
    }
    if (strnlen(user1, MAX_USERNAME_LEN + 1U) > MAX_USERNAME_LEN) {
        return PAM_AUTH_ERR;
    }

    status1 = load_user_secret(user1, secret1, sizeof(secret1), &fake1,
                               &user1_id);
    
    /* Handle nullok: If user has no secret, bypass the whole module */
    if (status1 == STATUS_NOT_FOUND && nullok) {
        /* SECURITY: Bypass approved via configuration */
        secure_memzero(secret1, sizeof(secret1));
        return PAM_IGNORE; 
    }

    /* Ask User 1 OTP (Always run prompt to prevent enumeration if file is missing but nullok NOT set) */
    char prompt_u1[128];
    int prompt_length = snprintf(prompt_u1, sizeof(prompt_u1),
                                 "Verification Code [%s]: ", user1);
    if (prompt_length < 0 || (size_t)prompt_length >= sizeof(prompt_u1)) {
        goto cleanup;
    }
    ret = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &otp1, "%s", prompt_u1);
    if (otp1 != NULL) otp1_len = strnlen(otp1, PAM_MAX_RESP_SIZE);
    if (ret != PAM_SUCCESS || otp1 == NULL) goto cleanup;

    if (verify_totp(user1, secret1, otp1, fake1, &counter1) != PAM_SUCCESS) {
        syslog(LOG_WARNING, "PAM_2MAN: User %s TOTP failed", user1);
        final_result = PAM_AUTH_ERR;
        goto cleanup;
    }
    int replay_status = totp_replay_check_and_store(
        "pam_2man_totp", user1_id, counter1);
    if (replay_status != TOTP_REPLAY_ACCEPTED) {
        syslog(replay_status == TOTP_REPLAY_DETECTED ? LOG_NOTICE : LOG_ERR,
               "PAM_2MAN: %s TOTP counter for user %s",
               replay_status == TOTP_REPLAY_DETECTED ? "Replayed" :
                                                       "Could not persist",
               user1);
        goto cleanup;
    }

    /* --- FASE 2: AUTORIZADOR (User 2) --- */
    ret = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &user2_input, "Authorizer Username (Wheel Group): ");
    if (user2_input != NULL) {
        user2_len = strnlen(user2_input, MAX_USERNAME_LEN + 1U);
    }
    if (ret != PAM_SUCCESS || user2_input == NULL) goto cleanup;
    if (user2_len > MAX_USERNAME_LEN) goto cleanup;

    if (strcmp(user1, user2_input) == 0) {
        syslog(LOG_WARNING, "PAM_2MAN: Self-auth attempt by %s", user1);
        final_result = PAM_AUTH_ERR;
        goto cleanup;
    }

    if (!is_user_privileged(user2_input, PRIVILEGED_GROUP)) {
        fake2 = 1; 
    } else {
        /* User 2 MUST have secret. nullok does not apply to Approver */
        load_user_secret(user2_input, secret2, sizeof(secret2), &fake2,
                         &user2_id);
    }

    char prompt_u2[128];
    prompt_length = snprintf(prompt_u2, sizeof(prompt_u2),
                             "Verification Code [%s]: ", user2_input);
    if (prompt_length < 0 || (size_t)prompt_length >= sizeof(prompt_u2)) {
        goto cleanup;
    }
    ret = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &otp2, "%s", prompt_u2);
    if (otp2 != NULL) otp2_len = strnlen(otp2, PAM_MAX_RESP_SIZE);
    if (ret != PAM_SUCCESS || otp2 == NULL) goto cleanup;

    if (verify_totp(user2_input, secret2, otp2, fake2, &counter2) == PAM_SUCCESS) {
        replay_status = totp_replay_check_and_store(
            "pam_2man_totp", user2_id, counter2);
        if (replay_status == TOTP_REPLAY_ACCEPTED) {
            syslog(LOG_NOTICE, "PAM_2MAN: Dual Auth Success (%s + %s)", user1, user2_input);
            final_result = PAM_SUCCESS;
        } else {
            syslog(replay_status == TOTP_REPLAY_DETECTED ? LOG_NOTICE : LOG_ERR,
                   "PAM_2MAN: %s TOTP counter for authorizer %s",
                   replay_status == TOTP_REPLAY_DETECTED ? "Replayed" :
                                                           "Could not persist",
                   user2_input);
            final_result = PAM_AUTH_ERR;
        }
    } else {
        syslog(LOG_WARNING, "PAM_2MAN: Authorizer %s TOTP failed", user2_input);
        final_result = PAM_AUTH_ERR;
    }

cleanup:
    secure_memzero(secret1, sizeof(secret1));
    secure_memzero(secret2, sizeof(secret2));
    if (otp1) secure_free((void**)&otp1, otp1_len);
    if (otp2) secure_free((void**)&otp2, otp2_len);
    if (user2_input) secure_free((void**)&user2_input, user2_len);

    if (final_result != PAM_SUCCESS) {
        pam_fail_delay(pamh, FAIL_DELAY_MS);
    }

    return final_result;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
