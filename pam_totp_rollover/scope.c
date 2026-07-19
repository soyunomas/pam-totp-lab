#define _POSIX_C_SOURCE 200809L

#include "scope.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TAG_DIGEST_BYTES 12U

int ptr_validate_service(const char *service)
{
    size_t length;

    if (service == NULL) return -1;
    length = strnlen(service, PTR_SERVICE_MAX_LENGTH + 1U);
    if (length == 0U || length > PTR_SERVICE_MAX_LENGTH) return -1;
    for (size_t i = 0U; i < length; i++) {
        unsigned char ch = (unsigned char)service[i];
        if (!((ch >= (unsigned char)'a' && ch <= (unsigned char)'z') ||
              (ch >= (unsigned char)'A' && ch <= (unsigned char)'Z') ||
              (ch >= (unsigned char)'0' && ch <= (unsigned char)'9') ||
              ch == (unsigned char)'_' || ch == (unsigned char)'-' ||
              ch == (unsigned char)'.')) {
            return -1;
        }
    }
    return 0;
}

int ptr_make_replay_tag(const char *service, const unsigned char *secret,
                        size_t secret_length,
                        char out[PTR_REPLAY_TAG_CAPACITY])
{
    EVP_MD_CTX *context = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0U;
    unsigned char separator = 0U;
    size_t offset = 4U;
    int result = -1;

    if (ptr_validate_service(service) != 0 || secret == NULL ||
        secret_length == 0U || secret_length > 128U || out == NULL) {
        return -1;
    }
    memset(digest, 0, sizeof(digest));
    memset(out, 0, PTR_REPLAY_TAG_CAPACITY);
    memcpy(out, "ptr_", 4U);

    context = EVP_MD_CTX_new();
    if (context == NULL ||
        EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(context, service, strlen(service)) != 1 ||
        EVP_DigestUpdate(context, &separator, sizeof(separator)) != 1 ||
        EVP_DigestUpdate(context, secret, secret_length) != 1 ||
        EVP_DigestFinal_ex(context, digest, &digest_length) != 1 ||
        digest_length < TAG_DIGEST_BYTES) {
        goto cleanup;
    }

    for (size_t i = 0U; i < TAG_DIGEST_BYTES; i++) {
        int written = snprintf(out + offset, PTR_REPLAY_TAG_CAPACITY - offset,
                               "%02x", (unsigned int)digest[i]);
        if (written != 2) goto cleanup;
        offset += 2U;
    }
    if (offset >= PTR_REPLAY_TAG_CAPACITY) goto cleanup;
    out[offset] = '\0';
    result = 0;

cleanup:
    EVP_MD_CTX_free(context);
    OPENSSL_cleanse(digest, sizeof(digest));
    if (result != 0) OPENSSL_cleanse(out, PTR_REPLAY_TAG_CAPACITY);
    return result;
}
