#define _GNU_SOURCE

#include "challenge.h"
#include "../pam_schedule_totp_override/rate_limit.h"
#include "../pam_schedule_totp_override/schedule.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define STATE_DIRECTORY "/var/lib/pam-schedule-partial-key"
#define HEADER_SIZE 41U
#define MAX_BITMAP 31248U

static int valid_directory(int fd, uid_t owner)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == owner &&
                   (st.st_mode & (mode_t)0077) == 0
               ? 0
               : -1;
}

static int valid_file(int fd, uid_t owner)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == owner &&
                   st.st_nlink == 1 &&
                   (st.st_mode & (mode_t)0777) == (mode_t)0600
               ? 0
               : -1;
}

static int random_below(uint32_t bound, uint32_t *out)
{
    uint32_t value;
    uint32_t limit;
    if (bound == 0U || out == NULL) return -1;
    limit = UINT32_MAX - (UINT32_MAX % bound);
    do {
        if (RAND_bytes((unsigned char *)&value, sizeof(value)) != 1) return -1;
    } while (value >= limit);
    *out = value % bound;
    return 0;
}

static void unrank(size_t rank, size_t length,
                   size_t positions[SPK_CHALLENGE_COUNT])
{
    size_t block = (length - 1U) * (length - 2U);
    size_t remainder;
    size_t second_rank;
    size_t third_rank;

    positions[0] = rank / block;
    remainder = rank % block;
    second_rank = remainder / (length - 2U);
    positions[1] = second_rank >= positions[0] ? second_rank + 1U : second_rank;
    third_rank = remainder % (length - 2U);
    for (size_t candidate = 0U; candidate < length; candidate++) {
        if (candidate == positions[0] || candidate == positions[1]) continue;
        if (third_rank == 0U) {
            positions[2] = candidate;
            return;
        }
        third_rank--;
    }
}

static int state_name(char out[72], uid_t uid, const char *username,
                      const char *service, const char *authorizer)
{
    EVP_MD_CTX *ctx = NULL;
    unsigned char digest[32];
    unsigned int length = 0U;
    int result = -1;

    if (out == NULL || pso_validate_username(username) != 0 ||
        pso_validate_service(service) != 0 ||
        pso_validate_authorizer_name(authorizer) != 0) {
        return -1;
    }
    ctx = EVP_MD_CTX_new();
    if (ctx != NULL && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, &uid, sizeof(uid)) == 1 &&
        EVP_DigestUpdate(ctx, username, strlen(username) + 1U) == 1 &&
        EVP_DigestUpdate(ctx, service, strlen(service) + 1U) == 1 &&
        EVP_DigestUpdate(ctx, authorizer, strlen(authorizer)) == 1 &&
        EVP_DigestFinal_ex(ctx, digest, &length) == 1 && length == 32U) {
        memcpy(out, "spk-", 4U);
        for (size_t i = 0U; i < 32U; i++) {
            (void)snprintf(out + 4U + (i * 2U), 3U, "%02x", digest[i]);
        }
        memcpy(out + 68U, ".st", 3U);
        out[71] = '\0';
        result = 0;
    }
    EVP_MD_CTX_free(ctx);
    pso_secure_memzero(digest, sizeof(digest));
    return result;
}

int spk_reserve_challenge_at(int directory_fd, uid_t expected_owner,
                             uid_t user_id, const char *username,
                             const char *service, const char *authorizer,
                             const unsigned char key_id[32], size_t pass_len,
                             size_t positions[SPK_CHALLENGE_COUNT])
{
    char name[72];
    unsigned char header[HEADER_SIZE];
    unsigned char *bitmap = NULL;
    size_t total;
    size_t bitmap_len;
    uint32_t start;
    int fd = -1;
    int reset = 0;
    int result = SPK_CHALLENGE_ERROR;
    struct stat st;

    if (key_id == NULL || positions == NULL || pass_len < 8U ||
        pass_len > 64U || valid_directory(directory_fd, expected_owner) != 0 ||
        state_name(name, user_id, username, service, authorizer) != 0) {
        return SPK_CHALLENGE_ERROR;
    }
    total = pass_len * (pass_len - 1U) * (pass_len - 2U);
    bitmap_len = (total + 7U) / 8U;
    if (bitmap_len == 0U || bitmap_len > MAX_BITMAP) return SPK_CHALLENGE_ERROR;
    bitmap = calloc(1U, bitmap_len);
    if (bitmap == NULL) return SPK_CHALLENGE_ERROR;

    fd = openat(directory_fd, name,
                O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
                (mode_t)0600);
    if (fd < 0 || flock(fd, LOCK_EX) != 0 ||
        valid_file(fd, expected_owner) != 0 || fstat(fd, &st) != 0) {
        goto cleanup;
    }
    if (st.st_size == 0) {
        reset = 1;
    } else if (st.st_size != (off_t)(HEADER_SIZE + bitmap_len) ||
               pread(fd, header, HEADER_SIZE, 0) != (ssize_t)HEADER_SIZE ||
               memcmp(header, "SPKST01", 7U) != 0 ||
               header[7] != 0U || header[8] != (unsigned char)pass_len) {
        goto cleanup;
    } else if (memcmp(header + 9U, key_id, 32U) != 0) {
        reset = 1;
    } else if (pread(fd, bitmap, bitmap_len, (off_t)HEADER_SIZE) !=
               (ssize_t)bitmap_len) {
        goto cleanup;
    }
    if (reset != 0) {
        memset(header, 0, sizeof(header));
        memcpy(header, "SPKST01", 7U);
        header[8] = (unsigned char)pass_len;
        memcpy(header + 9U, key_id, 32U);
        memset(bitmap, 0, bitmap_len);
        if (ftruncate(fd, 0) != 0 ||
            pwrite(fd, header, HEADER_SIZE, 0) != (ssize_t)HEADER_SIZE ||
            pwrite(fd, bitmap, bitmap_len, (off_t)HEADER_SIZE) !=
                (ssize_t)bitmap_len) {
            goto cleanup;
        }
    }
    if (random_below((uint32_t)total, &start) != 0) goto cleanup;
    for (size_t offset = 0U; offset < total; offset++) {
        size_t rank = ((size_t)start + offset) % total;
        unsigned char mask = (unsigned char)(1U << (rank & 7U));
        if ((bitmap[rank >> 3U] & mask) == 0U) {
            bitmap[rank >> 3U] = (unsigned char)(bitmap[rank >> 3U] | mask);
            if (pwrite(fd, &bitmap[rank >> 3U], 1U,
                       (off_t)(HEADER_SIZE + (rank >> 3U))) != 1 ||
                fsync(fd) != 0) {
                goto cleanup;
            }
            unrank(rank, pass_len, positions);
            result = SPK_CHALLENGE_OK;
            goto cleanup;
        }
    }
    result = SPK_CHALLENGE_EXHAUSTED;

cleanup:
    if (fd >= 0) close(fd);
    if (bitmap != NULL) {
        pso_secure_memzero(bitmap, bitmap_len);
        free(bitmap);
    }
    pso_secure_memzero(header, sizeof(header));
    return result;
}

int spk_reserve_challenge(uid_t user_id, const char *username,
                          const char *service, const char *authorizer,
                          const unsigned char key_id[32], size_t pass_len,
                          size_t positions[SPK_CHALLENGE_COUNT])
{
    int fd;
    int result;
    if (geteuid() != (uid_t)0) return SPK_CHALLENGE_ERROR;
    fd = open(STATE_DIRECTORY,
              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return SPK_CHALLENGE_ERROR;
    result = spk_reserve_challenge_at(fd, (uid_t)0, user_id, username,
                                      service, authorizer, key_id, pass_len,
                                      positions);
    close(fd);
    return result;
}
