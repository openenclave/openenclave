// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_CRYPTO_EC_H
#define _OE_HOST_CRYPTO_EC_H

#include <openenclave/internal/ec.h>
#include <openssl/evp.h>

/* Caller is responsible for validating parameters */
void OE_ECPublicKeyInit(OE_ECPublicKey* publicKey, EVP_PKEY* pkey);

#endif /* _OE_HOST_CRYPTO_EC_H */
