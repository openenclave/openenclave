// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/crypto/init.h>

/* Forward declaration */
int SC_OSSL_ENGINE_Initialize();

/* Add the implementation of the function (only available for OpenSSL)
 * to fulfill the linker requirement */
int SC_OSSL_ENGINE_Initialize()
{
    return OE_SYMCRYPT_ENGINE_INVALID;
}

/* oe_crypto_initialize will be invoked during the enclave initialization.
 * Do nothing here given that Mbed TLS does not require initialization
 * (while OpenSSL does). */
void oe_crypto_initialize(void)
{
}

int oe_is_symcrypt_engine_available()
{
    return 0;
}
