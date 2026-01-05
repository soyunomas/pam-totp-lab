/*
 * PAM CHRONOGUARD
 * Implementación de Seguridad Dinámica Basada en Tiempo
 * Diseño: "Sandwich" Time Strategy con FORMATO LIBRE (PRE=... POST=...)
 * Auditoría: Hardened C implementation (MISRA/CERT-C Compliance)
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
#include <ctype.h>
#include <errno.h>
#include <limits.h>     
#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* Configuración */
#define CONFIG_FILE ".chronoguard"
#define MAX_CONFIG_LINE 128
#define MAX_TIME_BUFFER 64

/* REGLA 14: Limpieza segura de memoria (Anti-Forensic) */
static void secure_memzero(void *s, size_t n) {
    if (!s || n == 0) return;
    volatile unsigned char *p = (volatile unsigned char *)s;
    while (n--) *p++ = 0;
    __asm__ __volatile__("" : : "r"(s) : "memory");
}

/* CONSTRUCTOR DE TIEMPO DINÁMICO */
static void build_time_string(const char *fmt, const struct tm *t, char *out_buf, size_t max_len) {
    if (!fmt || !out_buf || max_len == 0) return;
    
    memset(out_buf, 0, max_len);
    size_t current_len = 0;
    const char *p = fmt;
    char tmp[16]; 

    while (*p && current_len < (max_len - 1)) {
        memset(tmp, 0, sizeof(tmp));
        int added = 0;

        /* REGLA 20: Parsing exhaustivo */
        if (strncmp(p, "HH", 2) == 0) {
            snprintf(tmp, sizeof(tmp), "%02d", t->tm_hour);
            p += 2; added = 1;
        }
        else if (strncmp(p, "MI", 2) == 0) {
            snprintf(tmp, sizeof(tmp), "%02d", t->tm_min);
            p += 2; added = 1;
        }
        else if (strncmp(p, "DD", 2) == 0) {
            snprintf(tmp, sizeof(tmp), "%02d", t->tm_mday);
            p += 2; added = 1;
        }
        else if (strncmp(p, "MM", 2) == 0) {
            snprintf(tmp, sizeof(tmp), "%02d", t->tm_mon + 1);
            p += 2; added = 1;
        }
        else if (strncmp(p, "YY", 2) == 0 || strncmp(p, "AA", 2) == 0) {
            snprintf(tmp, sizeof(tmp), "%02d", t->tm_year % 100);
            p += 2; added = 1;
        }
        else if (strncmp(p, "YYYY", 4) == 0) {
            snprintf(tmp, sizeof(tmp), "%04d", t->tm_year + 1900);
            p += 4; added = 1;
        }
        else if (strncmp(p, "WD", 2) == 0) {
            snprintf(tmp, sizeof(tmp), "%d", (t->tm_wday == 0 ? 7 : t->tm_wday));
            p += 2; added = 1;
        }
        else {
            p++; /* Skip unknown char */
        }

        if (added) {
            size_t tmp_len = strlen(tmp);
            if (current_len + tmp_len < max_len) {
                strncat(out_buf, tmp, max_len - current_len - 1);
                current_len += tmp_len;
            } else {
                break; 
            }
        }
    }
}

/* Lectura segura de configuración con DROP PRIVILEGES */
static int get_user_config(const char *username, char *pre_fmt, char *post_fmt, size_t fmt_size) {
    long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) bufsize = 16384;

    char *buf = malloc((size_t)bufsize);
    if (!buf) return -1;

    struct passwd pwd;
    struct passwd *result = NULL;
    memset(&pwd, 0, sizeof(pwd));

    if (getpwnam_r(username, &pwd, buf, (size_t)bufsize, &result) != 0 || !result) {
        free(buf); return -1;
    }

    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", pwd.pw_dir, CONFIG_FILE) >= (int)sizeof(path)) {
        syslog(LOG_ERR, "PAM-CHRONOGUARD: Path truncation for user %s", username);
        free(buf); return -1;
    }

    /* --- INICIO ZONA CRÍTICA: PRIVILEGE DROP --- */
    /* Regla 1: Mínimo privilegio. Guardamos credenciales actuales */
    uid_t old_uid = geteuid();
    gid_t old_gid = getegid();
    
    /* Guardamos grupos para restaurar, pero no inicializamos grupos nuevos innecesariamente */
    int groups_n = getgroups(0, NULL);
    gid_t *groups = NULL;
    
    if (groups_n > 0) {
        groups = malloc(groups_n * sizeof(gid_t));
        if (!groups) { free(buf); return -1; }
        if (getgroups(groups_n, groups) == -1) { free(buf); free(groups); return -1; }
    }

    /* Drop temporal a usuario para leer su archivo */
    /* FIX: No usamos initgroups() aqui, solo necesitamos el UID/GID efectivo para leer el archivo */
    if (setegid(pwd.pw_gid) != 0 || seteuid(pwd.pw_uid) != 0) {
        free(buf); if(groups) free(groups); return -1;
    }

    FILE *fp = fopen(path, "r");
    int success = 0;
    
    if (fp) {
        struct stat st;
        /* Regla 12: Race Conditions - fstat sobre el descriptor abierto */
        if (fstat(fileno(fp), &st) == 0) {
            /* Regla 24: Verificación estricta de permisos (600 y propiedad) */
            if (S_ISREG(st.st_mode) && st.st_uid == pwd.pw_uid && (st.st_mode & 0077) == 0) {
                char line[MAX_CONFIG_LINE] = {0};
                memset(pre_fmt, 0, fmt_size);
                memset(post_fmt, 0, fmt_size);

                while (fgets(line, sizeof(line), fp)) {
                    line[strcspn(line, "\r\n")] = 0;
                    if (strncmp(line, "PRE=", 4) == 0) {
                        snprintf(pre_fmt, fmt_size, "%.*s", (int)(fmt_size - 1), line + 4);
                        success = 1; 
                    }
                    else if (strncmp(line, "POST=", 5) == 0) {
                        snprintf(post_fmt, fmt_size, "%.*s", (int)(fmt_size - 1), line + 5);
                        success = 1;
                    }
                }
            } else {
                syslog(LOG_ERR, "PAM-CHRONOGUARD: Insecure file permissions for %s (Require 0600)", path);
            }
        }
        fclose(fp);
    }

    /* Restaurar privilegios (Fail-Close: abortar si falla) */
    if (seteuid(old_uid) != 0 || setegid(old_gid) != 0) { 
        /* Regla 2: Fail-Safe. Si no podemos recuperar root, morimos. */
        abort(); 
    }
    
    /* Restaurar grupos si los hubiere */
    if (groups) { 
        if (setgroups(groups_n, groups) != 0) abort(); 
        free(groups); 
    } else {
        /* Si no habia grupos extra, limpiamos */
        setgroups(0, NULL);
    }
    /* --- FIN ZONA CRÍTICA --- */

    free(buf);
    return success ? 0 : -1;
}

/* PUNTO DE ENTRADA PRINCIPAL */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags; (void)argc; (void)argv;
    const char *username = NULL;
    const char *password = NULL;
    char *clean_pass = NULL;
    int retval = PAM_AUTH_ERR;

    openlog("pam_chronoguard", LOG_PID | LOG_CONS, LOG_AUTH);

    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username) return PAM_AUTH_ERR;

    char pre_fmt[MAX_TIME_BUFFER] = {0};
    char post_fmt[MAX_TIME_BUFFER] = {0};

    /* Si no hay config, ignoramos (auth optional support) */
    if (get_user_config(username, pre_fmt, post_fmt, sizeof(pre_fmt)) != 0) return PAM_IGNORE; 
    if (strlen(pre_fmt) == 0 && strlen(post_fmt) == 0) return PAM_IGNORE;

    if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password) != PAM_SUCCESS) return PAM_AUTH_ERR;
    
    if (!password) { 
        char *resp = NULL;
        retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &resp, "Password: ");
        if (retval != PAM_SUCCESS || !resp) return PAM_AUTH_ERR;
        pam_set_item(pamh, PAM_AUTHTOK, resp);
        password = resp; 
    }

    time_t now = time(NULL);
    struct tm t_buf; 
    struct tm *t = localtime_r(&now, &t_buf);
    
    char expected_pre[MAX_TIME_BUFFER] = {0};
    char expected_suf[MAX_TIME_BUFFER] = {0};

    build_time_string(pre_fmt, t, expected_pre, sizeof(expected_pre));
    build_time_string(post_fmt, t, expected_suf, sizeof(expected_suf));

    /* 
     * [SECURITY FIX] v2.4
     * Eliminado logging de debug que exponía credenciales.
     * Regla 27: No hardcoded secrets / no logging secrets.
     */
    
    size_t pre_len = strlen(expected_pre);
    size_t suf_len = strlen(expected_suf);
    size_t pass_len = strlen(password);
    size_t min_len = pre_len + suf_len + 1; 

    /* Validación de longitud para evitar underflows en la resta posterior */
    if (pass_len < min_len) {
        retval = PAM_AUTH_ERR;
        goto cleanup;
    }

    /* Verificación de Prefijo */
    if (pre_len > 0) {
        if (strncmp(password, expected_pre, pre_len) != 0) {
            retval = PAM_AUTH_ERR; 
            goto cleanup;
        }
    }

    /* Verificación de Sufijo */
    if (suf_len > 0) {
        const char *pass_suf_ptr = password + (pass_len - suf_len);
        if (strncmp(pass_suf_ptr, expected_suf, suf_len) != 0) {
            retval = PAM_AUTH_ERR; 
            goto cleanup;
        }
    }

    /* Extracción de la contraseña real "sandwicheada" */
    size_t clean_len = pass_len - pre_len - suf_len;
    clean_pass = malloc(clean_len + 1);
    if (!clean_pass) {
        retval = PAM_BUF_ERR;
        goto cleanup;
    }

    memcpy(clean_pass, password + pre_len, clean_len);
    clean_pass[clean_len] = '\0';

    /* Inyección de la contraseña limpia en el stack PAM */
    if (pam_set_item(pamh, PAM_AUTHTOK, clean_pass) != PAM_SUCCESS) {
        retval = PAM_AUTH_ERR;
        goto cleanup;
    }

    retval = PAM_SUCCESS;

cleanup:
    /* Limpieza Paranoica (Anti-Forensic) */
    if (clean_pass) {
        secure_memzero(clean_pass, clean_len);
        free(clean_pass);
    }
    secure_memzero(expected_pre, sizeof(expected_pre));
    secure_memzero(expected_suf, sizeof(expected_suf));
    secure_memzero(pre_fmt, sizeof(pre_fmt));
    secure_memzero(post_fmt, sizeof(post_fmt));
    closelog();
    return retval;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
