// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVE_KEY_H
#define _ENCLAVE_KEY_H

#include <mbedtls/pk.h>
#include <openenclave/bits/hash.h>
#include <openenclave/result.h>
#include <openenclave/types.h>

typedef struct _OE_PrivateKey
{
    uint64_t magic;
    mbedtls_pk_context pk;
} OE_PrivateKey;

typedef struct _OE_PublicKey
{
    uint64_t magic;
    mbedtls_pk_context pk;
} OE_PublicKey;

typedef OE_Result (*OE_CopyKey)(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool copyPrivateFields);

bool OE_PrivateKeyValid(const OE_PrivateKey* privateKey, uint64_t magic);

OE_Result OE_PrivateKeyInit(
    OE_PrivateKey* privateKey,
    const mbedtls_pk_context* pk,
    OE_CopyKey copyKey,
    uint64_t magic);

void OE_PrivateKeyRelease(OE_PrivateKey* privateKey, uint64_t magic);

bool OE_PublicKeyValid(const OE_PublicKey* publicKey, uint64_t magic);

OE_Result OE_PublicKeyInit(
    OE_PublicKey* publicKey,
    const mbedtls_pk_context* pk,
    OE_CopyKey copyKey,
    uint64_t magic);

void OE_PublicKeyRelease(OE_PublicKey* publicKey, uint64_t magic);

OE_Result OE_PrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_PrivateKey* privateKey,
    mbedtls_pk_type_t keyType,
    uint64_t magic);

OE_Result OE_PrivateKeyWritePEM(
    const OE_PrivateKey* privateKey,
    uint8_t* pemData,
    size_t* pemSize,
    uint64_t magic);

OE_Result OE_PublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_PublicKey* publicKey,
    mbedtls_pk_type_t keyType,
    uint64_t magic);

OE_Result OE_PublicKeyWritePEM(
    const OE_PublicKey* publicKey,
    uint8_t* pemData,
    size_t* pemSize,
    uint64_t magic);

OE_Result OE_PrivateKeyFree(OE_PrivateKey* privateKey, uint64_t magic);

OE_Result OE_PublicKeyFree(OE_PublicKey* publicKey, uint64_t magic);

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

#endif /* _ENCLAVE_KEY_H */
