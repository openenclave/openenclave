// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_CRYPTO_EC_H
#define _OE_HOST_CRYPTO_EC_H

#include <openenclave/bits/ec.h>
#include <openssl/evp.h>

/* Caller is responsible for validating parameters */
void oe_ec_public_key_init(oe_ec_public_key_t* publicKey, EVP_PKEY* pkey);

#endif /* _OE_HOST_CRYPTO_EC_H */
