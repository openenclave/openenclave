// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/crypto/init.h>

/* We do not have the SymCrypt engine available yet, defining a mock initializer
 * with the same function prototype and returns OE_SYMCRYPT_ENGINE_SUCCESS,
 * mimicking the expected behavior. */
int SC_OSSL_ENGINE_Initialize()
{
    return OE_SYMCRYPT_ENGINE_SUCCESS;
}
