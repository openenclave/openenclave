// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _HOST_CRYPTO_H
#define _HOST_CRYPTO_H

#include <openenclave/types.h>
#include <openenclave/result.h>
#include <openenclave/bits/hash.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

typedef OE_Result (*OE_WriteKey)(BIO* bio, EVP_PKEY* pkey);

typedef struct OE_PrivateKey
{
    uint64_t magic;
    EVP_PKEY* pkey;
} OE_PrivateKey;

typedef struct OE_PublicKey
{
    uint64_t magic;
    EVP_PKEY* pkey;
} OE_PublicKey;

bool OE_PrivateKeyValid(const OE_PrivateKey* impl, uint64_t magic);

bool OE_PublicKeyValid(const OE_PublicKey* impl, uint64_t magic);

void OE_PublicKeyInit(OE_PublicKey* publicKey, EVP_PKEY* pkey, uint64_t magic);

OE_Result OE_PrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_PrivateKey* key,
    int keyType,
    uint64_t magic);

OE_Result OE_PublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_PublicKey* key,
    int keyType,
    uint64_t magic);

OE_Result OE_PrivateKeyWritePEM(
    const OE_PrivateKey* privateKey,
    uint8_t* data,
    size_t* size,
    OE_WriteKey writeKey,
    uint64_t magic);

OE_Result OE_PublicKeyWritePEM(
    const OE_PublicKey* key,
    uint8_t* data,
    size_t* size,
    uint64_t magic);

OE_Result OE_PrivateKeyFree(OE_PrivateKey* key, uint64_t magic);

OE_Result OE_PublicKeyFree(OE_PublicKey* key, uint64_t magic);

OE_Result OE_PrivateKeySign(
    const OE_PrivateKey* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize,
    uint64_t magic);

OE_Result OE_PublicKeyVerify(
    const OE_PublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize,
    uint64_t magic);

#endif /* _HOST_CRYPTO_H */
