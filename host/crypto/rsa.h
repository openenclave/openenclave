// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_CRYPTO_RSA_H
#define _OE_HOST_CRYPTO_RSA_H

#include <openenclave/internal/rsa.h>
#include <openssl/evp.h>

/* Caller is responsible for validating parameters */
void OE_RSAPublicKeyInit(OE_RSAPublicKey* publicKey, EVP_PKEY* pkey);

#endif /* _OE_HOST_CRYPTO_RSA_H */
