// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _HOST_KEY_H
#define _HOST_KEY_H

#include <openenclave/bits/hash.h>
#include <openenclave/result.h>
#include <openenclave/types.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

typedef struct oe_private_key_t
{
    uint64_t magic;
    EVP_PKEY* pkey;
} oe_private_key_t;

typedef struct oe_public_key_t
{
    uint64_t magic;
    EVP_PKEY* pkey;
} oe_public_key_t;

typedef oe_result_t (*oe_private_key_write_pem_callback)(BIO* bio, EVP_PKEY* pkey);

bool oe_private_key_is_valid(const oe_private_key_t* impl, uint64_t magic);

bool oe_public_key_is_valid(const oe_public_key_t* impl, uint64_t magic);

void oe_public_key_init(oe_public_key_t* publicKey, EVP_PKEY* pkey, uint64_t magic);

void oe_private_key_init(
    oe_private_key_t* privateKey,
    EVP_PKEY* pkey,
    uint64_t magic);

oe_result_t oe_private_key_read_pem(
    const uint8_t* pemData,
    size_t pemSize,
    oe_private_key_t* key,
    int keyType,
    uint64_t magic);

oe_result_t oe_public_key_read_pem(
    const uint8_t* pemData,
    size_t pemSize,
    oe_public_key_t* key,
    int keyType,
    uint64_t magic);

oe_result_t oe_private_key_write_pem(
    const oe_private_key_t* privateKey,
    uint8_t* data,
    size_t* size,
    oe_private_key_write_pem_callback privateKeyWritePEMCallback,
    uint64_t magic);

oe_result_t oe_public_key_write_pem(
    const oe_public_key_t* key,
    uint8_t* data,
    size_t* size,
    uint64_t magic);

oe_result_t oe_private_key_free(oe_private_key_t* key, uint64_t magic);

oe_result_t oe_public_key_free(oe_public_key_t* key, uint64_t magic);

oe_result_t oe_private_key_sign(
    const oe_private_key_t* privateKey,
    oe_hash_type_t hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize,
    uint64_t magic);

oe_result_t oe_public_key_verify(
    const oe_public_key_t* publicKey,
    oe_hash_type_t hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize,
    uint64_t magic);

#endif /* _HOST_KEY_H */
