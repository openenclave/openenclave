// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/internal/crypto/init.h>

/* Forward declaration */
int SCOSSL_ENGINE_Initialize();
int OSSL_provider_init(
    const void* handle,
    const void* in,
    const void** out,
    void** provctx);

/* Add the implementation of the function (only available for OpenSSL)
 * to fulfill the linker requirement */
int SCOSSL_ENGINE_Initialize()
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

int oe_is_symcrypt_provider_available()
{
    return 0;
}

int OSSL_provider_init(
    const void* handle,
    const void* in,
    const void** out,
    void** provctx)
{
    OE_UNUSED(handle);
    OE_UNUSED(in);
    OE_UNUSED(out);
    OE_UNUSED(provctx);
    return 0;
}
