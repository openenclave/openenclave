// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_RSA_H
#define _OE_ENCLAVE_RSA_H

#include <mbedtls/pk.h>
#include <openenclave/internal/rsa.h>

OE_INLINE bool OE_IsRSAKey(const mbedtls_pk_context* pk)
{
    return (pk->pk_info == mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
}

OE_Result OE_RSAPublicKeyInit(
    OE_RSAPublicKey* publicKey,
    const mbedtls_pk_context* pk);

#endif /* _OE_ENCLAVE_RSA_H */
