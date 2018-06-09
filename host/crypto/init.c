// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "init.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <pthread.h>

static pthread_once_t _once = PTHREAD_ONCE_INIT;

static void _Initialize(void)
{
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
}

void oe_initialize_open_ssl(void)
{
    pthread_once(&_once, _Initialize);
}
