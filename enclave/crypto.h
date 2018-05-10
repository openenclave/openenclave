#ifndef _ENCLAVE_CRYPTO_H
#define _ENCLAVE_CRYPTO_H

#include <openenclave/types.h>

/*
**==============================================================================
**
** These functions manage the 'CryptoRefs' variable, which is a counter of
** unreleased objects created by the crypto library. This number should be
** zero after all objects have been released.
**
**==============================================================================
*/

uint64_t OE_CryptoRefsGet();

void OE_CryptoRefsIncrement();

void OE_CryptoRefsDecrement();

#endif /* _ENCLAVE_CRYPTO_H */
