// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/crypto/init.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <pthread.h>
static pthread_once_t _once = PTHREAD_ONCE_INIT;

static void _initialize(void)
{
    /*
     * The following code is used to support OpenSSL < 1.1.0 on the host. Will
     * be removed once we drop the support of older version of OpenSSL (along
     * with Ubuntu 16.04).
     */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
}

void oe_crypto_initialize(void)
{
    pthread_once(&_once, _initialize);
}
