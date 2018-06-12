// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_EC_H
#define _OE_ENCLAVE_EC_H

#include <mbedtls/pk.h>
#include <openenclave/internal/ec.h>

OE_INLINE bool OE_IsECKey(const mbedtls_pk_context* pk)
{
    return (pk->pk_info == mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
}

OE_Result OE_ECPublicKeyInit(
    OE_ECPublicKey* publicKey,
    const mbedtls_pk_context* pk);

#endif /* _OE_ENCLAVE_EC_H */
