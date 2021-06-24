// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_CRYPTO_INIT_H
#define _OE_INTERNAL_CRYPTO_INIT_H

/* Initialize OE crypto. */
void oe_crypto_initialize(void);

/* Value 0 and 1 are defined by the SymCrypt
 * engine implementation. */
#define OE_SYMCRYPT_ENGINE_FAIL 0
#define OE_SYMCRYPT_ENGINE_SUCCESS 1
#define OE_SYMCRYPT_ENGINE_NOT_LINKED 2
#define OE_SYMCRYPT_ENGINE_INVALID 3

int oe_is_symcrypt_engine_available();

#endif /* _OE_INTERNAL_CRYPTO_INIT_H */
