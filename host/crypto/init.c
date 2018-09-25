// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "init.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#ifdef _WIN32
#include <Windows.h>
#else
#include <pthread.h>
#endif

#ifdef _WIN32
INIT_ONCE _once = INIT_ONCE_STATIC_INIT;
#else
static pthread_once_t _once = PTHREAD_ONCE_INIT;
#endif

static void _initialize(void)
{
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
}

#ifdef _WIN32
BOOL CALLBACK _initialize_wrapper(PINIT_ONCE  init_once, PVOID p, PVOID* ctx)
{
    _initialize();
    return TRUE;
}
#endif

void oe_initialize_openssl(void)
{
#ifdef _WIN32
    InitOnceExecuteOnce(&_once, _initialize_wrapper, NULL, NULL);
#else
	pthread_once(&_once, _initialize);
#endif
}
