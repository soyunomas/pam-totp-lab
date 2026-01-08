/*
 * PAM SCHOOL SCHEDULE - HARDENED V2
 * Context-Aware Authentication Module
 *
 * AUDIT FIXES:
 * 1. Side-Channel/Timing protection (Fake Token generation).
 * 2. Complete Privilege Dropping (Supplementary Groups).
 * 3. Environment Sanitization (TZ Spoofing).
 * 4. True Constant Time Comparison.
 *
 * AUTHOR: Soyunomas
 * LICENSE: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

/* PAM Headers */
#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* CONSTANTS */
#define CONFIG_FILE ".school_schedule"
#define MAX_LINE_LEN 256
#define MAX_TOKEN_LEN 64
/* Delay in microseconds for failed attempts (2 seconds) */
#define AUTH_DELAY 2000000 

/* Days mapping */
static const char *DAYS[] = {"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"};

/*
 * SECURITY HELPER: Secure Memory Wipe
 */
static void secure_memzero(void *s, size_t n) {
    if (!s || n == 0) return;
    volatile unsigned char *p = (volatile unsigned char *)s;
    while (n--) *p++ = 0;
    __asm__ __volatile__("" : : "r"(s) : "memory");
}

/*
 * SECURITY FIX #4: TRUE Constant Time Comparison
 * Scans the full buffer length regardless of string length
 * to prevent length leakage.
 */
static int secure_equals_const(const char *a, const char *b) {
    if (!a || !b) return 0;
    
    volatile unsigned char result = 0;
    /* Always iterate MAX_TOKEN_LEN to hide actual length */
    for (size_t i = 0; i < MAX_TOKEN_LEN; i++) {
        char c1 = (i < strlen(a)) ? a[i] : 0;
        char c2 = (i < strlen(b)) ? b[i] : 0;
        result |= (unsigned char)(c1 ^ c2);
    }
    
    return (result == 0);
}

/*
 * SECURITY FIX #5: Prompt Sanitization
 */
static void sanitize_string(const char *input, char *output, size_t out_len) {
    size_t j = 0;
    for (size_t i = 0; input[i] != '\0' && j < out_len - 1; i++) {
        if (isalnum((unsigned char)input[i]) || input[i] == '.' || input[i] == '-' || input[i] == '_') {
            output[j++] = input[i];
        } else {
            output[j++] = '?'; 
        }
    }
    output[j] = '\0';
}

/* Helper functions */
static int parse_time_to_minutes(const char *time_str) {
    if (!time_str || strlen(time_str) != 5) return -1;
    if (time_str[2] != ':') return -1;
    if (!isdigit((unsigned char)time_str[0]) || !isdigit((unsigned char)time_str[1]) ||
        !isdigit((unsigned char)time_str[3]) || !isdigit((unsigned char)time_str[4])) return -1;

    char *endptr;
    long h = strtol(time_str, &endptr, 10);
    if (*endptr != ':') return -1;
    long m = strtol(time_str + 3, &endptr, 10);
    if (*endptr != '\0') return -1;
    if (h < 0 || h > 23 || m < 0 || m > 59) return -1;
    return (int)((h * 60) + m);
}

static int parse_day(const char *day_str) {
    if (!day_str) return -1;
    for (int i = 0; i < 7; i++) {
        if (strncasecmp(day_str, DAYS[i], 3) == 0) return i;
    }
    return -1;
}

static void expand_token(const char *template, char *out, size_t max_len, const struct tm *now_tm) {
    size_t i = 0, j = 0;
    size_t t_len = strlen(template);
    memset(out, 0, max_len);
    while (i < t_len && j < (max_len - 1)) {
        if (template[i] == '%' && (i + 1) < t_len) {
            char tmp[4] = {0};
            int added = 0;
            switch (template[i+1]) {
                case 'H': snprintf(tmp, sizeof(tmp), "%02d", now_tm->tm_hour); added = 1; break;
                case 'M': snprintf(tmp, sizeof(tmp), "%02d", now_tm->tm_min); added = 1; break;
                case '%': tmp[0] = '%'; tmp[1] = '\0'; added = 1; break;
                default: break;
            }
            if (added) {
                size_t tmp_len = strlen(tmp);
                if (j + tmp_len < max_len) {
                    memcpy(out + j, tmp, tmp_len);
                    j += tmp_len;
                }
                i += 2; continue;
            }
        }
        out[j++] = template[i++];
    }
    out[j] = '\0';
}

/*
 * CORE: Get Token securely
 * SECURITY FIX #2: Drops Supplementary Groups
 */
static int get_expected_token(const char *username, char *token_out, size_t token_size) {
    long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) bufsize = 16384;
    char *buf = malloc((size_t)bufsize);
    if (!buf) return -1;

    struct passwd pwd;
    struct passwd *result = NULL;
    memset(&pwd, 0, sizeof(pwd));

    if (getpwnam_r(username, &pwd, buf, (size_t)bufsize, &result) != 0 || !result) {
        secure_memzero(buf, (size_t)bufsize);
        free(buf);
        return -1;
    }

    char filepath[PATH_MAX];
    if (snprintf(filepath, sizeof(filepath), "%s/%s", pwd.pw_dir, CONFIG_FILE) >= (int)sizeof(filepath)) {
        secure_memzero(buf, (size_t)bufsize);
        free(buf);
        return -1;
    }

    /* SAVE PRIVILEGES */
    uid_t old_uid = geteuid();
    gid_t old_gid = getegid();
    int groups_n = getgroups(0, NULL);
    gid_t *groups = NULL;

    if (groups_n > 0) {
        if ((size_t)groups_n > SIZE_MAX / sizeof(gid_t)) {
             secure_memzero(buf, (size_t)bufsize); free(buf); return -1;
        }
        groups = malloc((size_t)groups_n * sizeof(gid_t));
        if (!groups || getgroups(groups_n, groups) == -1) {
            free(groups); secure_memzero(buf, (size_t)bufsize); free(buf); return -1;
        }
    }

    /* DROP PRIVILEGES (FULL) */
    /* Fix #2: Clear supplementary groups first */
    if (setgroups(0, NULL) != 0) {
        /* If we can't clear groups, fail securely */
        secure_memzero(buf, (size_t)bufsize); free(buf); if(groups) free(groups); return -1;
    }
    if (setegid(pwd.pw_gid) != 0 || seteuid(pwd.pw_uid) != 0) {
        secure_memzero(buf, (size_t)bufsize); free(buf); if(groups) free(groups); return -1;
    }

    /* READ FILE */
    int fd = open(filepath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    FILE *fp = NULL;
    if (fd >= 0) fp = fdopen(fd, "r");

    int found = 0;
    if (fp) {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            if (S_ISREG(st.st_mode) && st.st_uid == pwd.pw_uid && (st.st_mode & 0077) == 0) {
                time_t now = time(NULL);
                struct tm now_tm;
                localtime_r(&now, &now_tm); 
                int now_minutes = (now_tm.tm_hour * 60) + now_tm.tm_min;
                int now_wday = now_tm.tm_wday; 
                char line[MAX_LINE_LEN];
                while (fgets(line, sizeof(line), fp)) {
                    char *saveptr;
                    char *day_str = strtok_r(line, " \t\r\n", &saveptr);
                    char *start_str = strtok_r(NULL, " \t\r\n", &saveptr);
                    char *end_str = strtok_r(NULL, " \t\r\n", &saveptr);
                    char *raw_token = strtok_r(NULL, " \t\r\n", &saveptr);
                    if (!day_str || !start_str || !end_str || !raw_token) continue;
                    int cfg_day = parse_day(day_str);
                    int start_min = parse_time_to_minutes(start_str);
                    int end_min = parse_time_to_minutes(end_str);
                    if (cfg_day == -1 || start_min == -1 || end_min == -1) continue;
                    if (cfg_day == now_wday && now_minutes >= start_min && now_minutes < end_min) {
                        expand_token(raw_token, token_out, token_size, &now_tm);
                        found = 1;
                        break;
                    }
                }
            } else {
                syslog(LOG_ERR, "PAM_SCHOOL: Insecure permissions on %s", filepath);
            }
        }
        fclose(fp);
    } else {
         if (errno == ELOOP) syslog(LOG_ERR, "PAM_SCHOOL: Symlink attack on %s", filepath);
    }

    /* RESTORE PRIVILEGES */
    if (seteuid(old_uid) != 0 || setegid(old_gid) != 0) abort();
    if (groups) {
        if (setgroups(groups_n, groups) != 0) abort();
        free(groups);
    } else {
        /* If original had no groups, ensure we have none now or default */
        /* setgroups(0, NULL) was called earlier, so strictly we are clean. 
           But ideally we restore "no groups" state if that was the state. */
    }

    secure_memzero(buf, (size_t)bufsize);
    free(buf);
    return (found) ? 0 : -1;
}

/*
 * PAM ENTRY POINT
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags;

    /* SECURITY FIX #3: Timezone Spoofing Prevention */
    /* Force system timezone to avoid environment attacks */
    unsetenv("TZ");
    tzset();

    int nullok = 0;
    for (int i = 0; i < argc; i++) {
        if (argv[i] && strcmp(argv[i], "nullok") == 0) nullok = 1;
    }

    const char *username = NULL;
    char *password = NULL; 
    char expected_token[MAX_TOKEN_LEN] = {0};
    
    /* Variables for Dummy/Fake logic */
    int is_valid_session = 0;
    int config_result = -1;

    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username) {
        return PAM_AUTH_ERR;
    }

    /* Try to get the token */
    config_result = get_expected_token(username, expected_token, sizeof(expected_token));

    /* 
     * SECURITY FIX #1: TIMING ATTACK MITIGATION
     * Logic: We ALWAYS prompt and ALWAYS compare.
     * If configuration is missing/invalid, we generate a fake token to compare against.
     */
    if (config_result == 0) {
        /* Real token found */
        is_valid_session = 1;
    } else {
        /* No class or no file. 
           If nullok is set, we might return IGNORE, BUT doing so immediately leaks info.
           However, standard PAM behavior for nullok usually skips.
           To be 100% secure against enumeration, we should fake it, 
           but that breaks 'nullok' functionality which is explicitly "allow if missing".
           
           DECISION: 
           - If 'nullok' is ON: We behave as requested (Allow access).
           - If 'nullok' is OFF: We MUST FAKE the auth to prevent timing attacks.
        */
        if (nullok) {
            return PAM_IGNORE; 
        }

        /* Generate fake random token for comparison */
        is_valid_session = 0;
        snprintf(expected_token, sizeof(expected_token), "FAKE_%d_%d", rand(), rand());
    }

    /* Prompt User */
    char safe_username[64];
    char prompt[128];
    sanitize_string(username, safe_username, sizeof(safe_username));
    snprintf(prompt, sizeof(prompt), "Materia Actual (%s): ", safe_username);
    
    char *resp = NULL;
    int prompt_retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &resp, "%s", prompt);
    
    if (prompt_retval != PAM_SUCCESS || !resp) {
        secure_memzero(expected_token, sizeof(expected_token));
        return prompt_retval;
    }
    password = resp;

    /* COMPARE (Always perform this step) */
    int compare_result = secure_equals_const(password, expected_token);

    /* FINAL DECISION */
    int final_retval = PAM_AUTH_ERR;

    if (is_valid_session && compare_result) {
        final_retval = PAM_SUCCESS;
    } else {
        /* 
         * Failed (either wrong password OR not in class).
         * We delay here to normalize timing. 
         */
        final_retval = PAM_AUTH_ERR;
        pam_fail_delay(pamh, AUTH_DELAY);
    }

    /* Cleanup */
    secure_memzero(expected_token, sizeof(expected_token));
    if (password) {
        secure_memzero(password, strlen(password));
        free(password); 
    }
    
    return final_retval;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
