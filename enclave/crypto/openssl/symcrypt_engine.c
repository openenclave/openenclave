// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/internal/crypto/init.h>

/* When the enclave does not opt into the SymCrypt engine at link time,
 * the following implementation (weak) will be picked by the linker.
 * Note that we have to put the function in a separated source file from
 * init.c to prevent the linker pulls in the symbol along with the
 * oe_crypto_initialize function. */
int _oe_scossl_engine_initialize()
{
    return OE_SYMCRYPT_ENGINE_NOT_LINKED;
}
OE_WEAK_ALIAS(_oe_scossl_engine_initialize, SCOSSL_ENGINE_Initialize);
