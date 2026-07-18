#ifndef OATH_H
#define OATH_H
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#define OATH_OK 0
#define OATH_CRYPTO_ERROR (-1)
int oath_init(void);
int oath_base32_decode(const char *, size_t, char **, size_t *);
int oath_totp_validate3(const char *, size_t, time_t, unsigned int, time_t,
                        unsigned int, unsigned int *, uint64_t *, const char *);
#endif
