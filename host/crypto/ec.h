#ifndef _OE_HOST_CRYPTO_EC_H
#define _OE_HOST_CRYPTO_EC_H

#include <openenclave/bits/ec.h>
#include <openssl/evp.h>

/* Caller is responsible for validating parameters */
void OE_ECInitPublicKey(OE_ECPublicKey* publicKey, EVP_PKEY* pkey);

/* Caller is responsible for validating parameters */
void OE_ECInitPrivateKey(OE_ECPrivateKey* privateKey, EVP_PKEY* pkey);

#endif /* _OE_HOST_CRYPTO_EC_H */
