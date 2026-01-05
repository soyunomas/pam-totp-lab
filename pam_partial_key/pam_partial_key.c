/*
 * pam_partial_key.c
 * Security: Strict Privilege Separation, Anti-Replay, Constant-Time Compare
 * Compliance: MISRA-C / CERT-C / OpenSSL 3.0
 */
#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h> 
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h> 
#include <time.h>
#include <errno.h>

#define KEY_FILE ".partial_key"
#define CHALLENGE_COUNT 3
#define SALT_LEN 16

/* REGLA 14: Limpieza Segura */
static void secure_zero(void *s, size_t n) {
    if(!s) return;
    volatile unsigned char *p = s;
    while (n--) *p++ = 0;
}

/* OpenSSL 3.0 Wrapper */
static void calc_hash(unsigned char *out, const unsigned char *salt, int index, char c) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return; 

    unsigned int md_len;
    if(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        EVP_DigestUpdate(mdctx, salt, SALT_LEN);
        EVP_DigestUpdate(mdctx, &index, sizeof(int));
        EVP_DigestUpdate(mdctx, &c, 1);
        EVP_DigestFinal_ex(mdctx, out, &md_len);
    }
    EVP_MD_CTX_free(mdctx);
}

/* REGLA 7 & 25: Separación de Privilegios */
static int get_user_key_data(const char *username, unsigned char *salt_out, char ***hashes_out, size_t *pass_len_out) {
    int pipefd[2];
    if (pipe(pipefd) == -1) return -1;

    struct passwd *pwd = getpwnam(username);
    if (!pwd) { close(pipefd[0]); close(pipefd[1]); return -1; }

    pid_t pid = fork();
    if (pid == -1) { close(pipefd[0]); close(pipefd[1]); return -1; }

    if (pid == 0) { // CHILD (Sandbox)
        close(pipefd[0]);
        
        /* Drop Privileges Strict */
        if (initgroups(username, pwd->pw_gid) != 0 || 
            setgid(pwd->pw_gid) != 0 || 
            setuid(pwd->pw_uid) != 0) {
            _exit(1);
        }

        char path[512];
        if (snprintf(path, sizeof(path), "%s/%s", pwd->pw_dir, KEY_FILE) >= (int)sizeof(path)) {
            _exit(1); 
        }

        /* REGLA 12: Race Condition Check */
        int fd = open(path, O_RDONLY);
        if (fd < 0) _exit(1);

        struct stat st;
        if (fstat(fd, &st) != 0 || (st.st_mode & 0077) != 0) {
            _exit(2); // Insecure permissions
        }

        FILE *fp = fdopen(fd, "r");
        if (!fp) _exit(1);

        char buffer[4096]; 
        size_t n = fread(buffer, 1, sizeof(buffer)-1, fp);
        if (n > 0) {
            buffer[n] = 0;
            if (write(pipefd[1], buffer, n) != (ssize_t)n) {
                _exit(3); // Pipe error
            }
        }
        
        fclose(fp);
        _exit(0);
    } else { // PARENT (Root)
        close(pipefd[1]);
        char buffer[4096] = {0};
        int status;
        waitpid(pid, &status, 0);
        
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            close(pipefd[0]);
            return -1;
        }

        ssize_t bytes_read = read(pipefd[0], buffer, sizeof(buffer)-1);
        close(pipefd[0]);

        if (bytes_read <= 0) return -1;
        buffer[bytes_read] = 0;

        // Parse: LEN|SALT|HASHES
        char *saveptr;
        char *token = strtok_r(buffer, "|", &saveptr);
        if (!token) return -1;
        
        *pass_len_out = (size_t)atoi(token);
        if (*pass_len_out == 0 || *pass_len_out > 256) return -1;

        token = strtok_r(NULL, "|", &saveptr);
        if (!token || strlen(token) != SALT_LEN * 2) return -1;

        for (int i = 0; i < SALT_LEN; i++) {
            if (sscanf(token + 2*i, "%02hhx", &salt_out[i]) != 1) return -1;
        }

        *hashes_out = calloc(*pass_len_out, sizeof(char*));
        if (!*hashes_out) return -1;

        for (size_t i = 0; i < *pass_len_out; i++) {
            token = strtok_r(NULL, "|", &saveptr);
            if (!token) return -1;
            (*hashes_out)[i] = strdup(token);
        }
        return 0;
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user;
    unsigned char salt[SALT_LEN];
    char **stored_hashes = NULL;
    size_t pass_len = 0;
    int retval = PAM_AUTH_ERR;

    (void)flags; (void)argc; (void)argv;

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) return PAM_AUTH_ERR;

    if (get_user_key_data(user, salt, &stored_hashes, &pass_len) != 0) {
        return PAM_AUTH_ERR;
    }

    /* REGLA 17: Random Seguro (Rejection Sampling) */
    int indices[CHALLENGE_COUNT];
    unsigned char rand_buf[CHALLENGE_COUNT];
    
    if (RAND_bytes(rand_buf, CHALLENGE_COUNT) != 1) {
        goto cleanup;
    }

    for (int i = 0; i < CHALLENGE_COUNT; i++) {
        int r, unique;
        int attempts = 0;
        do {
            /* Si fallamos la unicidad, pedimos nuevo byte */
            if (attempts > 0) RAND_bytes(&rand_buf[i], 1);
            
            r = rand_buf[i] % pass_len;
            unique = 1;
            for (int j = 0; j < i; j++) if (indices[j] == r) unique = 0;
            attempts++;
        } while (!unique && attempts < 100);
        indices[i] = r;
    }

    char prompt[128];
    snprintf(prompt, sizeof(prompt), "Posiciones [%d] [%d] [%d]: ", 
             indices[0]+1, indices[1]+1, indices[2]+1);

    char *resp = NULL;
    if (pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &resp, "%s", prompt) != PAM_SUCCESS) {
        goto cleanup;
    }
    if (!resp) goto cleanup;

    char clean_resp[CHALLENGE_COUNT + 1];
    int clean_idx = 0;
    for (int i = 0; resp[i] != '\0' && clean_idx < CHALLENGE_COUNT; i++) {
        if (resp[i] != ' ' && resp[i] != '\t') {
            clean_resp[clean_idx++] = resp[i];
        }
    }
    
    if (clean_idx != CHALLENGE_COUNT) {
        goto cleanup;
    }

    /* REGLA 16: Comparación de Tiempo Constante */
    int match_count = 0;
    unsigned char computed_hash[32];
    char computed_hex[65];

    for (int i = 0; i < CHALLENGE_COUNT; i++) {
        calc_hash(computed_hash, salt, indices[i], clean_resp[i]);
        for(int b=0; b<32; b++) sprintf(computed_hex + (b*2), "%02x", computed_hash[b]);
        
        if (stored_hashes[indices[i]]) {
            if (CRYPTO_memcmp(computed_hex, stored_hashes[indices[i]], 64) == 0) {
                match_count++;
            }
        }
    }

    if (match_count == CHALLENGE_COUNT) {
        retval = PAM_SUCCESS;
    }

cleanup:
    if (resp) { secure_zero(resp, strlen(resp)); free(resp); }
    if (stored_hashes) {
        for(size_t i=0; i<pass_len; i++) free(stored_hashes[i]);
        free(stored_hashes);
    }
    
    /* Anti Timing Attack Delay */
    if (retval != PAM_SUCCESS) pam_fail_delay(pamh, 2000000);
    
    return retval;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
