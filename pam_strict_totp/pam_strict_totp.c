/*
 * ==============================================================================
 *  PAM STRICT TOTP - High Security 2FA Module
 * ==============================================================================
 *
 *  Author:      Soyunomas
 *  Repository:  https://github.com/soyunomas/pam-totp-lab
 *  License:     MIT
 *
 *  Description:
 *  A hardened PAM module for Time-based One-Time Passwords (TOTP/RFC 6238).
 *  Designed with a "Security First" mindset, following MISRA-C guidelines
 *  and OpenBSD secure coding practices.
 *
 *  Key Features:
 *   - Fail-Close Architecture (Deny by default on error).
 *   - Strict Privilege Separation (Drops root before file access).
 *   - Zero-Memory Residency (Secrets are wiped immediately).
 *   - Anti-Timing Attack mitigations (Constant time execution path).
 *
 *  DISCLAIMER:
 *  This software is provided "as is" without warranty of any kind.
 *  Use in critical systems at your own risk.
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
#include <sys/prctl.h>  
#include <stdint.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <liboath/oath.h>

#define SECRET_FILE ".google_authenticator"
#define MIN_SECRET_LEN 16
#define MAX_SECRET_LEN 128

/* CONFIGURACIÓN TOTP */
#define TOTP_STEP_SIZE 30  /* Estándar RFC 6238: 30 segundos */
#define TOTP_WINDOW    1   /* Ventana de tolerancia: +/- 1 paso (30s) */
#define FAIL_DELAY     3000000 

#define SECRET_OK           0
#define SECRET_NOT_FOUND    1
#define SECRET_ERROR        -1

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

static int get_user_secret(const char *username, char *secret_buf, size_t buf_size) {
    int retval = SECRET_ERROR;
    
    long bufsize_pwd = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize_pwd == -1) bufsize_pwd = 16384;

    char *buf_pwd = calloc(1, (size_t)bufsize_pwd);
    if (!buf_pwd) return SECRET_ERROR;

    struct passwd pwd;
    struct passwd *result = NULL;
    memset(&pwd, 0, sizeof(pwd));

    if (getpwnam_r(username, &pwd, buf_pwd, (size_t)bufsize_pwd, &result) != 0 || result == NULL) {
        secure_free((void**)&buf_pwd, (size_t)bufsize_pwd);
        return SECRET_ERROR;
    }

    char filepath[PATH_MAX];
    if (snprintf(filepath, sizeof(filepath), "%s/%s", pwd.pw_dir, SECRET_FILE) >= (int)sizeof(filepath)) {
        syslog(LOG_ERR, "PAM-TOTP: Path truncation for user %s", username);
        secure_free((void**)&buf_pwd, (size_t)bufsize_pwd);
        return SECRET_ERROR;
    }

    uid_t old_uid = geteuid();
    gid_t old_gid = getegid();
    
    int original_ngroups = getgroups(0, NULL);
    gid_t *original_groups = NULL;
    
    if (original_ngroups > 0) {
        original_groups = malloc((size_t)original_ngroups * sizeof(gid_t));
        if (!original_groups) {
            secure_free((void**)&buf_pwd, (size_t)bufsize_pwd);
            return SECRET_ERROR; 
        }
        if (getgroups(original_ngroups, original_groups) == -1) {
            secure_free((void**)&buf_pwd, (size_t)bufsize_pwd);
            free(original_groups);
            return SECRET_ERROR;
        }
    }

    /* DROP PRIVILEGES */
    if (initgroups(username, pwd.pw_gid) != 0 ||
        setegid(pwd.pw_gid) != 0 ||
        seteuid(pwd.pw_uid) != 0) {
        
        secure_free((void**)&buf_pwd, (size_t)bufsize_pwd);
        if (original_groups) free(original_groups);
        return SECRET_ERROR;
    }

    int fd = open(filepath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    FILE *fp = NULL;

    if (fd != -1) {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            if (S_ISREG(st.st_mode) && 
                st.st_uid == pwd.pw_uid && 
                (st.st_mode & 0077) == 0) { 
                
                fp = fdopen(fd, "r");
                if (!fp) close(fd);
            } else {
                syslog(LOG_WARNING, "PAM-TOTP: Insecure file permissions for user %s", username);
                close(fd);
            }
        } else {
            close(fd);
        }
    } else {
        if (errno == ENOENT) {
            retval = SECRET_NOT_FOUND;
        }
    }

    /* RESTAURAR PRIVILEGIOS */
    int restore_error = 0;
    if (seteuid(old_uid) != 0) restore_error = 1;
    if (!restore_error) {
        if (setegid(old_gid) != 0) restore_error = 1;
        if (original_ngroups > 0 && original_groups) {
            if (setgroups(original_ngroups, original_groups) != 0) restore_error = 1;
        } else {
            if (setgroups(0, NULL) != 0) restore_error = 1;
        }
    }

    if (restore_error) {
        syslog(LOG_CRIT, "PAM-TOTP: CRITICAL - Cannot restore privileges. Aborting.");
        if (fp) fclose(fp);
        secure_free((void**)&buf_pwd, (size_t)bufsize_pwd);
        if (original_groups) free(original_groups);
        abort(); 
    }

    secure_free((void**)&buf_pwd, (size_t)bufsize_pwd);
    if (original_groups) free(original_groups);

    if (fp) {
        if (fgets(secret_buf, (int)buf_size, fp) != NULL) {
            size_t len = strnlen(secret_buf, buf_size);
            while(len > 0 && (secret_buf[len-1] == '\n' || secret_buf[len-1] == '\r' || secret_buf[len-1] == ' ')) {
                secret_buf[len-1] = '\0';
                len--;
            }

            if (len >= MIN_SECRET_LEN && len <= MAX_SECRET_LEN) {
                retval = SECRET_OK;
            } else {
                syslog(LOG_WARNING, "PAM-TOTP: Invalid secret length for user %s", username);
                retval = SECRET_ERROR;
            }
        }
        fclose(fp);
    } else if (retval != SECRET_NOT_FOUND) {
        retval = SECRET_ERROR;
    }

    if (retval != SECRET_OK) secure_memzero(secret_buf, buf_size);
    return retval;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags;

    const char *username = NULL;
    char *otp_input = NULL;
    char secret_base32[256] = {0};
    char *secret_binary = NULL;
    size_t secret_binary_len = 0;
    size_t otp_input_len = 0;
    int retval = PAM_AUTH_ERR;
    int nullok = 0;

    for (int i = 0; i < argc; i++) {
        if (argv[i] && strcmp(argv[i], "nullok") == 0) {
            nullok = 1;
        }
    }

    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || username == NULL) {
        return PAM_AUTH_ERR;
    }

    int secret_status = get_user_secret(username, secret_base32, sizeof(secret_base32));

    int fake_mode = 0;
    if (secret_status != SECRET_OK) {
        if (secret_status == SECRET_NOT_FOUND && nullok) {
            return PAM_IGNORE; 
        }
        fake_mode = 1;
        strncpy(secret_base32, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", sizeof(secret_base32)-1);
    }

    retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &otp_input, "Verification Code: ");

    if (otp_input != NULL) {
        otp_input_len = strnlen(otp_input, PAM_MAX_RESP_SIZE);
    }
    if (retval != PAM_SUCCESS) {
        goto cleanup;
    }
    if (otp_input == NULL) {
        retval = PAM_AUTH_ERR;
        goto cleanup;
    }

    if (otp_input_len == PAM_MAX_RESP_SIZE || otp_input_len < 6U ||
        otp_input_len > 8U) {
        retval = PAM_AUTH_ERR;
        goto cleanup;
    }

    for (size_t i = 0; i < otp_input_len; i++) {
        if (otp_input[i] < '0' || otp_input[i] > '9') {
            retval = PAM_AUTH_ERR;
            goto cleanup;
        }
    }

    int rc = oath_base32_decode(secret_base32, strlen(secret_base32), &secret_binary, &secret_binary_len);
    secure_memzero(secret_base32, sizeof(secret_base32));

    if (rc != OATH_OK) {
        if (!fake_mode) syslog(LOG_ERR, "PAM-TOTP: Base32 decode failed for user %s", username);
        retval = PAM_AUTH_ERR;
        goto cleanup;
    }

    time_t now = time(NULL);
    
    /* FIX: Llamada correcta con paso de 30s y ventana de tolerancia */
    rc = oath_totp_validate3(secret_binary, secret_binary_len, 
                             now, 
                             TOTP_STEP_SIZE,   /* PASO DE TIEMPO (30s) */
                             0,                /* Inicio (0) */
                             TOTP_WINDOW,      /* VENTANA (1 paso extra) */
                             NULL, NULL, 
                             otp_input);

    if (rc == OATH_OK && !fake_mode) {
        retval = PAM_SUCCESS;
    } else {
        retval = PAM_AUTH_ERR;
        if (!fake_mode) syslog(LOG_NOTICE, "PAM-TOTP: Invalid OTP attempt for user %s", username);
    }

cleanup:
    secure_memzero(secret_base32, sizeof(secret_base32));
    if (secret_binary) secure_free((void**)&secret_binary, secret_binary_len);
    if (otp_input) secure_free((void**)&otp_input, otp_input_len);

    if (retval != PAM_SUCCESS) {
        pam_fail_delay(pamh, FAIL_DELAY);
    }

    return retval;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
