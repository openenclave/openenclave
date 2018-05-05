// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_RSA_H
#define _OE_ENCLAVE_RSA_H

#include <mbedtls/pk.h>
#include <openenclave/bits/rsa.h>

bool OE_IsRSAKey(const mbedtls_pk_context* pk);

OE_Result OE_RSAPublicKeyInitFrom(
    OE_RSAPublicKey* publicKey, 
    const mbedtls_pk_context* pk);

#endif /* _OE_ENCLAVE_RSA_H */
