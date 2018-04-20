#ifndef _OE_HOST_CRYPTO_RSA_H
#define _OE_HOST_CRYPTO_RSA_H

#include <openenclave/bits/rsa.h>
#include <openssl/rsa.h>

/* Caller is responsible for validating parameters */
void OE_RSAInitPublicKey(OE_RSAPublicKey* publicKey, RSA* rsa);

/* Caller is responsible for validating parameters */
void OE_RSAInitPrivateKey(OE_RSAPrivateKey* privateKey, RSA* rsa);

#endif /* _OE_HOST_CRYPTO_RSA_H */
