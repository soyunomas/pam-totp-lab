/*
 * PAM SCHOOL SCHEDULE
 * Context-Aware Authentication Module for Teachers
 *
 * SECURITY: MISRA-C / CERT-C Compliant
 * AUTHOR: Soyunomas
 * LICENSE: MIT
 *
 * NOTE: _GNU_SOURCE is defined in Makefile.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> /* FIX: Necesario para SIZE_MAX */
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

/* Days mapping */
static const char *DAYS[] = {"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"};

/*
 * SECURITY HELPER: Secure Memory Wipe
 * Rule 14: Clear secrets from RAM
 */
static void secure_memzero(void *s, size_t n) {
    if (!s || n == 0) return;
    volatile unsigned char *p = (volatile unsigned char *)s;
    while (n--) *p++ = 0;
    __asm__ __volatile__("" : : "r"(s) : "memory");
}

/*
 * HELPER: Parse "HH:MM" to minutes from midnight
 * Rule 26: Input Validation
 */
static int parse_time_to_minutes(const char *time_str) {
    if (!time_str || strlen(time_str) != 5) return -1;
    if (time_str[2] != ':') return -1;
    
    if (!isdigit((unsigned char)time_str[0]) || !isdigit((unsigned char)time_str[1]) ||
        !isdigit((unsigned char)time_str[3]) || !isdigit((unsigned char)time_str[4])) {
        return -1;
    }

    int h = atoi(time_str);      /* atoi safe here due to isdigit checks */
    int m = atoi(time_str + 3);

    if (h < 0 || h > 23 || m < 0 || m > 59) return -1;
    
    return (h * 60) + m;
}

/*
 * HELPER: Resolve Day String to Integer (0=SUN...6=SAT)
 */
static int parse_day(const char *day_str) {
    if (!day_str) return -1;
    for (int i = 0; i < 7; i++) {
        if (strncasecmp(day_str, DAYS[i], 3) == 0) {
            return i;
        }
    }
    return -1;
}

/*
 * LOGIC: Expand Dynamic Variables (%H, %M)
 * Rule 1: Bounded Strings (snprintf)
 */
static void expand_token(const char *template, char *out, size_t max_len, const struct tm *now_tm) {
    size_t i = 0, j = 0;
    size_t t_len = strlen(template);

    memset(out, 0, max_len);

    while (i < t_len && j < (max_len - 1)) {
        if (template[i] == '%' && (i + 1) < t_len) {
            char tmp[4] = {0};
            int added = 0;
            
            switch (template[i+1]) {
                case 'H':
                    snprintf(tmp, sizeof(tmp), "%02d", now_tm->tm_hour);
                    added = 1;
                    break;
                case 'M':
                    snprintf(tmp, sizeof(tmp), "%02d", now_tm->tm_min);
                    added = 1;
                    break;
                case '%':
                    tmp[0] = '%'; tmp[1] = '\0';
                    added = 1;
                    break;
                default:
                    /* Unknown variable, ignore */
                    break;
            }

            if (added) {
                size_t tmp_len = strlen(tmp);
                if (j + tmp_len < max_len) {
                    memcpy(out + j, tmp, tmp_len);
                    j += tmp_len;
                }
                i += 2; /* Skip %X */
                continue;
            }
        }
        
        out[j++] = template[i++];
    }
    out[j] = '\0';
}

/*
 * CORE: Read Config and Find Current Class Token
 * Principle 7: Separation of Privileges (Drop root before read)
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
    /* Rule 1: Truncation check */
    if (snprintf(filepath, sizeof(filepath), "%s/%s", pwd.pw_dir, CONFIG_FILE) >= (int)sizeof(filepath)) {
        secure_memzero(buf, (size_t)bufsize);
        free(buf);
        return -1;
    }

    /* --- PRIVILEGE DROP START --- */
    uid_t old_uid = geteuid();
    gid_t old_gid = getegid();
    
    int groups_n = getgroups(0, NULL);
    gid_t *groups = NULL;
    
    if (groups_n > 0) {
        /* Rule 4: Integer Overflow Check */
        if ((size_t)groups_n > SIZE_MAX / sizeof(gid_t)) {
            secure_memzero(buf, (size_t)bufsize);
            free(buf);
            return -1;
        }

        groups = malloc((size_t)groups_n * sizeof(gid_t));
        if (!groups) {
            secure_memzero(buf, (size_t)bufsize);
            free(buf);
            return -1;
        }
        
        if (getgroups(groups_n, groups) == -1) {
            free(groups);
            secure_memzero(buf, (size_t)bufsize);
            free(buf);
            return -1;
        }
    }

    /* Drop to user */
    if (setegid(pwd.pw_gid) != 0 || seteuid(pwd.pw_uid) != 0) {
        secure_memzero(buf, (size_t)bufsize);
        free(buf);
        if(groups) free(groups);
        return -1;
    }

    FILE *fp = fopen(filepath, "r");
    int found = 0;

    if (fp) {
        struct stat st;
        /* Rule 12: Race Condition Check (fstat on fd) */
        if (fstat(fileno(fp), &st) == 0) {
            /* Rule 24: Permission Check (0600) */
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

                    /* CHECK MATCH */
                    if (cfg_day == now_wday && now_minutes >= start_min && now_minutes < end_min) {
                        expand_token(raw_token, token_out, token_size, &now_tm);
                        found = 1;
                        break;
                    }
                }

            } else {
                syslog(LOG_ERR, "PAM_SCHOOL: Insecure permissions on %s. Require 0600.", filepath);
            }
        }
        fclose(fp);
    }

    /* --- PRIVILEGE RESTORE --- */
    if (seteuid(old_uid) != 0 || setegid(old_gid) != 0) {
        abort(); /* Rule 2: Fail-Close */
    }
    
    if (groups) {
        if (setgroups(groups_n, groups) != 0) {
             abort();
        }
        free(groups);
    } else {
        if (setgroups(0, NULL) != 0) {
            /* Fail secure if cannot clear groups */
        }
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

    /* 0. Parse Arguments to check for "nullok" */
    int nullok = 0;
    for (int i = 0; i < argc; i++) {
        if (argv[i] && strcmp(argv[i], "nullok") == 0) {
            nullok = 1;
        }
    }

    const char *username = NULL;
    char *password = NULL; 
    char expected_token[MAX_TOKEN_LEN] = {0};
    int retval = PAM_AUTH_ERR;

    /* 1. Get User */
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username) {
        return PAM_AUTH_ERR;
    }

    /* 2. Determine Expected Token based on Schedule */
    if (get_expected_token(username, expected_token, sizeof(expected_token)) != 0) {
        /* CONFIG NOT FOUND or NO CLASS SCHEDULED */
        if (nullok) {
            return PAM_IGNORE;
        }
        /* Default: Fail-Close */
        return PAM_AUTH_ERR;
    }

    /* 3. Get Password from User */
    char prompt[128];
    snprintf(prompt, sizeof(prompt), "Materia Actual (%s): ", username);
    
    char *resp = NULL;
    retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &resp, "%s", prompt);
    
    if (retval != PAM_SUCCESS || !resp) {
        secure_memzero(expected_token, sizeof(expected_token));
        return retval;
    }
    password = resp;

    /* 4. Compare */
    if (strcmp(password, expected_token) == 0) {
        retval = PAM_SUCCESS;
    } else {
        retval = PAM_AUTH_ERR;
        pam_fail_delay(pamh, 2000000); 
    }

    /* Cleanup */
    secure_memzero(expected_token, sizeof(expected_token));
    if (password) {
        secure_memzero(password, strlen(password));
        free(password); 
    }
    
    return retval;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
