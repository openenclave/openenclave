// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_RSA_H
#define _OE_ENCLAVE_RSA_H

#include <mbedtls/pk.h>
#include <openenclave/bits/rsa.h>
#include <openenclave/types.h>

/* Randomly generated magic number */
#define OE_RSA_PUBLIC_KEY_MAGIC 0x713600af058c447a

typedef struct _RSAPublicKey
{
    uint64_t magic;
    mbedtls_pk_context pk;
} RSAPublicKey;

OE_STATIC_ASSERT(sizeof(RSAPublicKey) <= sizeof(OE_RSAPublicKey));

int OE_RSACopyKey(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool clearPrivateFields);

OE_INLINE bool OE_IsRSAKey(const mbedtls_pk_context* pk)
{
    if (pk->pk_info != mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))
        return false;

    return true;
}

#endif /* _OE_ENCLAVE_RSA_H */
