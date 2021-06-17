// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>

/* When the enclave does not opt into the SymCrypt engine at link time,
 * the following implementation (weak) will be picked by the linker.
 * Note that we have to put the function in a separated source file from
 * init.c to prevent the linker pulls in the symbol along with the
 * oe_crypto_initialize function. */
int _SYMCRYPT_ENGINE_Initialize()
{
    return 0;
}
OE_WEAK_ALIAS(_SYMCRYPT_ENGINE_Initialize, SYMCRYPT_ENGINE_Initialize);
