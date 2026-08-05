#include "secure_memory.h"

#include <openssl/crypto.h>

void secure_memory_clear(void *buffer, size_t length)
{
    if (buffer != NULL && length != 0U) {
        OPENSSL_cleanse(buffer, length);
    }
}
