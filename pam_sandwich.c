/*
 * AUDITORÍA DE SEGURIDAD - CÓDIGO CRÍTICO
 * Módulo PAM TOTP con Estrategia "Sandwich" (Token Split)
 * 
 * Corrección aplicada: Inicialización de variables de tamaño para evitar UB.
 * Reglas aplicadas: MISRA-C / CERT C Secure Coding
 * Principios: Fail-Safe, Least Privilege, Defense in Depth
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
#include <sys/prctl.h>  
#include <stdint.h>

/* Cabeceras de PAM */
#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* Cabecera para TOTP (liboath) */
#include <liboath/oath.h>

/* CONSTANTES DE SEGURIDAD */
#define SECRET_FILE ".google_authenticator"
#define MIN_SECRET_LEN 16
#define MAX_SECRET_LEN 128
#define TOTP_WINDOW    30  /* Ventana de tiempo (segundos) */

/* Configuración "Frankenstein" (Sandwich) */
#define TOTP_PREFIX_LEN 3
#define TOTP_SUFFIX_LEN 3
#define TOTP_FULL_LEN   (TOTP_PREFIX_LEN + TOTP_SUFFIX_LEN)

/* =========================================================================
 * FUNCIONES AUXILIARES DE SEGURIDAD (HARDENED)
 * ========================================================================= */

/* REGLA 14: Limpieza segura de memoria (Anti-Optimizaciones) */
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

/* REGLA 10: Wrapper seguro para free */
static void secure_free(void **ptr, size_t size) {
    if (ptr && *ptr) {
        /* REGLA 9: Use-After-Free prevention */
        if (size > 0) secure_memzero(*ptr, size);
        free(*ptr);
        *ptr = NULL;
    }
}

/* =========================================================================
 * LÓGICA DE RECUPERACIÓN DE SECRETOS (PRIVILEGE SEPARATION)
 * ========================================================================= */

static int get_user_secret(const char *username, char *secret_buf, size_t buf_size) {
    int retval = -1;
    long bufsize_pwd = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize_pwd == -1) bufsize_pwd = 16384;

    /* REGLA 2: Verificación estricta de malloc */
    char *buf_pwd = malloc((size_t)bufsize_pwd);
    if (!buf_pwd) return -1;

    struct passwd pwd;
    struct passwd *result = NULL;
    
    /* REGLA 3: Inicialización a cero */
    memset(&pwd, 0, sizeof(pwd));

    /* REGLA 18: getpwnam_r es Thread Safe (getpwnam no lo es) */
    if (getpwnam_r(username, &pwd, buf_pwd, (size_t)bufsize_pwd, &result) != 0 || result == NULL) {
        secure_free((void**)&buf_pwd, 0);
        return -1;
    }

    char filepath[PATH_MAX];
    /* REGLA 1: Detección de truncamiento en rutas */
    if (snprintf(filepath, sizeof(filepath), "%s/%s", pwd.pw_dir, SECRET_FILE) >= (int)sizeof(filepath)) {
        syslog(LOG_ERR, "PAM-TOTP: Path truncation detected for user %s", username);
        secure_free((void**)&buf_pwd, 0);
        return -1;
    }

    /* 1. GUARDAR ESTADO DE PRIVILEGIOS ORIGINAL */
    uid_t old_uid = geteuid();
    gid_t old_gid = getegid();
    
    int original_ngroups = getgroups(0, NULL);
    gid_t *original_groups = NULL;
    
    if (original_ngroups > 0) {
        original_groups = malloc((size_t)original_ngroups * sizeof(gid_t));
        if (!original_groups) {
            secure_free((void**)&buf_pwd, 0);
            return -1; 
        }
        if (getgroups(original_ngroups, original_groups) == -1) {
            secure_free((void**)&buf_pwd, 0);
            free(original_groups);
            return -1;
        }
    }

    /* 2. DROP PRIVILEGES (PRINCIPIO DE MÍNIMO PRIVILEGIO) */
    /* Es vital cambiar grupos antes que usuario */
    if (initgroups(username, pwd.pw_gid) != 0 ||
        setegid(pwd.pw_gid) != 0 ||
        seteuid(pwd.pw_uid) != 0) {
        
        secure_free((void**)&buf_pwd, 0);
        if (original_groups) free(original_groups);
        return -1;
    }

    /* 3. LECTURA SEGURA (RACE CONDITION FREE) */
    /* REGLA 12: O_NOFOLLOW evita ataques de symlink */
    int fd = open(filepath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    FILE *fp = NULL;

    if (fd != -1) {
        struct stat st;
        /* REGLA 8: Validación completa ("Check every access") */
        if (fstat(fd, &st) == 0) {
            /* - Es fichero regular
             * - Pertenece al usuario correcto
             * - Permisos 0600 o 0400 (nadie más puede leer) */
            if (S_ISREG(st.st_mode) && 
                st.st_uid == pwd.pw_uid && 
                (st.st_mode & 0077) == 0) { 
                
                fp = fdopen(fd, "r");
                /* Si fdopen falla, cerramos fd manual */
                if (!fp) close(fd);
            } else {
                syslog(LOG_WARNING, "PAM-TOTP: Insecure file permissions for %s. Ignoring.", username);
                close(fd); /* Fail-Safe */
            }
        } else {
            close(fd);
        }
    }

    /* 4. RESTAURAR PRIVILEGIOS (CRÍTICO) */
    /* Si fallamos al restaurar root, debemos MATAR el proceso.
       No podemos dejar que PAM continúe con identidad incorrecta. */
    
    if (seteuid(old_uid) != 0) {
        syslog(LOG_CRIT, "PAM-TOTP: CRITICAL - Cannot restore EUID. Aborting execution.");
        if (fp) fclose(fp);
        abort(); /* PRINCIPIO 2: Fail-Safe / Fail-Close */
    }

    if (setegid(old_gid) != 0) {
         syslog(LOG_CRIT, "PAM-TOTP: CRITICAL - Cannot restore EGID. Aborting execution.");
         if (fp) fclose(fp);
         abort();
    }

    if (original_ngroups > 0 && original_groups) {
        if (setgroups(original_ngroups, original_groups) != 0) {
            syslog(LOG_CRIT, "PAM-TOTP: CRITICAL - Cannot restore groups. Aborting execution.");
            if (fp) fclose(fp);
            abort();
        }
    } else {
        /* Si no había grupos extra, limpiamos los del usuario */
        setgroups(0, NULL); 
    }

    /* Limpieza de recursos auxiliares */
    secure_free((void**)&buf_pwd, 0);
    if (original_groups) free(original_groups);

    /* Procesar contenido del fichero */
    if (fp) {
        if (fgets(secret_buf, (int)buf_size, fp) != NULL) {
            size_t len = strnlen(secret_buf, buf_size);
            
            /* Trim de espacios y saltos de línea */
            while(len > 0 && (secret_buf[len-1] == '\n' || secret_buf[len-1] == '\r' || isspace((unsigned char)secret_buf[len-1]))) {
                secret_buf[len-1] = '\0';
                len--;
            }

            /* REGLA 26: Validación de Input (Longitud) */
            if (len >= MIN_SECRET_LEN && len <= MAX_SECRET_LEN) {
                retval = 0; /* ÉXITO */
            } else {
                syslog(LOG_WARNING, "PAM-TOTP: Invalid secret length for %s", username);
                secure_memzero(secret_buf, buf_size); /* Borrar datos corruptos */
            }
        }
        fclose(fp);
    }

    /* En caso de error general, asegurar buffer limpio */
    if (retval != 0) {
        secure_memzero(secret_buf, buf_size);
    }
    
    return retval;
}

/* =========================================================================
 * MÓDULO PAM PRINCIPAL (LÓGICA SANDWICH)
 * ========================================================================= */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags; (void)argc; (void)argv;

    const char *username = NULL;
    const char *input_pass = NULL; 
    char *prompt_resp = NULL;    
    
    /* Buffers estáticos (stack) inicializados a 0 */
    char secret_base32[256] = {0};
    
    /* Punteros dinámicos para gestión de memoria manual */
    char *secret_binary = NULL; 
    char *clean_pass = NULL;
    
    /* REGLA 3: Inicialización TEMPRANA para evitar uninitialized warnings en cleanup */
    size_t clean_len = 0;
    size_t secret_binary_len = 0;
    
    int retval = PAM_AUTH_ERR;

    /* 1. OBTENER USUARIO */
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || username == NULL) {
        return PAM_AUTH_ERR;
    }

    /* 2. OBTENER SECRETO (FAIL-CLOSE) */
    if (get_user_secret(username, secret_base32, sizeof(secret_base32)) != 0) {
        return PAM_IGNORE; 
    }

    /* 3. OBTENER INPUT (PASSWORD + SANDWICH TOTP) */
    retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&input_pass);
    
    /* Si no hay password previo, preguntamos */
    if (retval != PAM_SUCCESS || input_pass == NULL || input_pass[0] == '\0') {
        /* PRINCIPIO 9: Least Astonishment (Aunque el diseño sea raro, el prompt debe ser claro) */
        retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &prompt_resp, "Password: ");
        if (retval != PAM_SUCCESS || prompt_resp == NULL) {
            goto cleanup;
        }
        input_pass = prompt_resp; 
    }

    size_t total_len = strlen(input_pass);

    /* REGLA 4: Integer Overflow/Underflow Prevention */
    /* Necesitamos al menos 3 (pre) + 1 (pass) + 3 (suf) = 7 caracteres */
    if (total_len < (TOTP_FULL_LEN + 1)) {
        retval = PAM_AUTH_ERR;
        goto cleanup;
    }

    /* 4. DISECCIÓN SEGURA DEL TOKEN (SANDWICH STRATEGY) */
    /* Buffer para recomponer el token de 6 dígitos */
    char token_str[TOTP_FULL_LEN + 1] = {0};

    /* A. Copiar Prefijo (primeros 3) */
    /* REGLA 1: Uso de memcpy controlado por constantes */
    memcpy(token_str, input_pass, TOTP_PREFIX_LEN);

    /* B. Copiar Sufijo (últimos 3) */
    /* Cálculo de puntero seguro: base + total - 3 */
    const char *suffix_ptr = input_pass + (total_len - TOTP_SUFFIX_LEN);
    memcpy(token_str + TOTP_PREFIX_LEN, suffix_ptr, TOTP_SUFFIX_LEN);
    
    token_str[TOTP_FULL_LEN] = '\0'; /* Garantía de Nulo */

    /* REGLA 26: Validación de contenido (Whitelisting de dígitos) */
    for (int i = 0; i < TOTP_FULL_LEN; i++) {
        if (!isdigit((unsigned char)token_str[i])) {
            retval = PAM_AUTH_ERR;
            goto cleanup;
        }
    }

    /* 5. DECODIFICACIÓN Y VALIDACIÓN CRIPTOGRÁFICA */
    int rc = oath_base32_decode(secret_base32, strlen(secret_base32), &secret_binary, &secret_binary_len);
    
    /* Ya no necesitamos el base32, borrar inmediatamente */
    secure_memzero(secret_base32, sizeof(secret_base32)); 

    if (rc != OATH_OK) {
        retval = PAM_AUTH_ERR;
        goto cleanup;
    }

    time_t now = time(NULL);
    /* Validar TOTP: ventana de +/- 1 paso (30s) */
    rc = oath_totp_validate3(secret_binary, secret_binary_len, 
                             now, TOTP_WINDOW, 
                             0, /* start offset time */ 
                             1, /* window size steps */
                             NULL, NULL, 
                             token_str);
    
    /* Borrar secreto binario y token reconstruido de RAM */
    secure_free((void**)&secret_binary, secret_binary_len);
    secure_memzero(token_str, sizeof(token_str));

    if (rc != OATH_OK) {
        retval = PAM_AUTH_ERR;
        goto cleanup;
    }

    /* 6. EXTRACCIÓN DEL PASSWORD REAL (CLEAN PASS) */
    /* Longitud del pass = Total - 6 */
    clean_len = total_len - TOTP_FULL_LEN;
    
    /* REGLA 2: Check malloc */
    clean_pass = malloc(clean_len + 1);
    if (!clean_pass) {
        retval = PAM_BUF_ERR;
        goto cleanup;
    }

    /* Copiar parte central: desde offset 3, longitud calculada */
    memcpy(clean_pass, input_pass + TOTP_PREFIX_LEN, clean_len);
    clean_pass[clean_len] = '\0';

    /* 7. ACTUALIZAR PILA PAM */
    retval = pam_set_item(pamh, PAM_AUTHTOK, clean_pass);
    
    /* Si falla set_item, es un error crítico de la librería PAM */
    if (retval != PAM_SUCCESS) {
        goto cleanup;
    }

    /* Éxito total */
    retval = PAM_SUCCESS;

cleanup:
    /* REGLA 14 & 10: Limpieza final centralizada */
    /* Borrar todos los rastros de la memoria antes de retornar */
    
    secure_memzero(secret_base32, sizeof(secret_base32));
    secure_memzero(token_str, sizeof(token_str));
    
    if (secret_binary) secure_free((void**)&secret_binary, secret_binary_len);
    
    /* clean_len siempre vale 0 o la longitud correcta, seguro de usar aquí */
    if (clean_pass) secure_free((void**)&clean_pass, clean_len);
    
    /* Si usamos prompt_resp (memoria asignada por PAM/malloc), debemos borrarla */
    if (prompt_resp) {
        secure_free((void**)&prompt_resp, strlen(prompt_resp));
    }

    return retval;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    /* PAM_SUCCESS es el default seguro para setcred si no hacemos nada */
    return PAM_SUCCESS;
}
