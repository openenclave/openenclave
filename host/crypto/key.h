#ifndef _HOST_CRYPTO_H
#define _HOST_CRYPTO_H

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/types.h>
#include <openenclave/result.h>
#include <openenclave/bits/hash.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

typedef OE_Result (*WriteKey)(BIO* bio, EVP_PKEY* pkey);

typedef struct _PrivateKey
{
    uint64_t magic;
    EVP_PKEY* pkey;
} PrivateKey;

typedef struct _PublicKey
{
    uint64_t magic;
    EVP_PKEY* pkey;
} PublicKey;

bool _PrivateKeyValid(const PrivateKey* impl, uint64_t magic);

bool _PublicKeyValid(const PublicKey* impl, uint64_t magic);

void _PublicKeyInit(PublicKey* publicKey, EVP_PKEY* pkey, uint64_t magic);

OE_Result _PrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    PrivateKey* key,
    int keyType,
    uint64_t magic);

OE_Result _PublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    PublicKey* key,
    int keyType,
    uint64_t magic);

OE_Result _PrivateKeyWritePEM(
    const PrivateKey* privateKey,
    uint8_t* data,
    size_t* size,
    WriteKey writeKey,
    uint64_t magic);

OE_Result _PublicKeyWritePEM(
    const PublicKey* key,
    uint8_t* data,
    size_t* size,
    uint64_t magic);

OE_Result _PrivateKeyFree(PrivateKey* key, uint64_t magic);

OE_Result _PublicKeyFree(PublicKey* key, uint64_t magic);

OE_Result _PrivateKeySign(
    const PrivateKey* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize,
    uint64_t magic);

OE_Result _PublicKeyVerify(
    const PublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize,
    uint64_t magic);

#endif /* _HOST_CRYPTO_H */
