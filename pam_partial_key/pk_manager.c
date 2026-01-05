/* 
 * pk_manager.c - Tool to generate partial key files
 * Security: OpenSSL 3.0, Secure UMASK, Memory Sanitization
 */
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <sys/stat.h>

#define KEY_FILE ".partial_key"
#define SALT_LEN 16
#define MAX_PASS_LEN 64

/* OpenSSL 3.0 EVP Wrapper */
void generate_pos_hash(unsigned char *out, const unsigned char *salt, int index, char c) {
    EVP_MD_CTX *mdctx;
    unsigned int md_len;

    mdctx = EVP_MD_CTX_new();
    if(!mdctx) { perror("EVP_MD_CTX_new"); exit(1); }

    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) { perror("EVP_Init"); exit(1); }
    if(1 != EVP_DigestUpdate(mdctx, salt, SALT_LEN)) { perror("EVP_Update"); exit(1); }
    if(1 != EVP_DigestUpdate(mdctx, &index, sizeof(int))) { perror("EVP_Update"); exit(1); }
    if(1 != EVP_DigestUpdate(mdctx, &c, 1)) { perror("EVP_Update"); exit(1); }
    
    if(1 != EVP_DigestFinal_ex(mdctx, out, &md_len)) { perror("EVP_Final"); exit(1); }

    EVP_MD_CTX_free(mdctx);
}

int main() {
    char password[MAX_PASS_LEN + 1];
    unsigned char salt[SALT_LEN];
    unsigned char hash[EVP_MAX_MD_SIZE];
    FILE *fp;
    char path[256];

    printf("=== Partial Key Setup (Secure Edition) ===\n");
    printf("Define your Banking-Style Password (Max %d chars): ", MAX_PASS_LEN);
    
    if (fgets(password, sizeof(password), stdin) == NULL) return 1;
    password[strcspn(password, "\n")] = 0;
    size_t len = strlen(password);

    if (len < 8) {
        printf("Error: Password too short (min 8).\n");
        return 1;
    }

    /* REGLA 17: Random Seguro */
    if (RAND_bytes(salt, SALT_LEN) != 1) {
        fprintf(stderr, "Fatal: OpenSSL CSPRNG failed.\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/%s", getenv("HOME"), KEY_FILE);
    
    /* REGLA 13: Evitar Race Condition con umask previo */
    mode_t old_mask = umask(0077);
    fp = fopen(path, "w");
    if (!fp) {
        perror("fopen");
        umask(old_mask);
        return 1;
    }
    
    /* Restaurar mascara por cortesía, aunque el programa acaba */
    umask(old_mask);

    // Format: LENGTH | SALT_HEX | HASH_0 | HASH_1 ...
    fprintf(fp, "%zu|", len);
    for(int i=0; i<SALT_LEN; i++) fprintf(fp, "%02x", salt[i]);
    fprintf(fp, "|");

    for(size_t i=0; i<len; i++) {
        generate_pos_hash(hash, salt, (int)i, password[i]);
        for(int j=0; j<32; j++) fprintf(fp, "%02x", hash[j]);
        if (i < len - 1) fprintf(fp, "|");
    }
    fprintf(fp, "\n");
    fclose(fp);

    printf("[OK] Key stored in %s with permissions 0600.\n", path);
    
    /* REGLA 14: Limpieza de RAM */
    volatile unsigned char *p = (volatile unsigned char *)password;
    size_t n = sizeof(password);
    while(n--) *p++ = 0;
    
    return 0;
}
