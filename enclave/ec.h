// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_EC_H
#define _OE_ENCLAVE_EC_H

#include <mbedtls/pk.h>
#include <openenclave/bits/ec.h>

bool OE_IsECKey(const mbedtls_pk_context* pk);

OE_Result OE_ECPublicKeyInitFrom(
    OE_ECPublicKey* publicKey, 
    const mbedtls_pk_context* pk);

#endif /* _OE_ENCLAVE_EC_H */
