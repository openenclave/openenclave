// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "init.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <pthread.h>

static pthread_once_t _once = PTHREAD_ONCE_INIT;

static void _initialize(void)
{
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
}

void oe_initialize_openssl(void)
{
    pthread_once(&_once, _initialize);
}
