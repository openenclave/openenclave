// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVE_KEY_H
#define _ENCLAVE_KEY_H

#include <mbedtls/pk.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/hash.h>

typedef struct _oe_private_key
{
    uint64_t magic;
    mbedtls_pk_context pk;
} oe_private_key_t;

typedef struct _oe_public_key
{
    uint64_t magic;
    mbedtls_pk_context pk;
} oe_public_key_t;

typedef oe_result_t (*oe_copy_key)(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool copyPrivateFields);

bool oe_private_key_is_valid(
    const oe_private_key_t* privateKey,
    uint64_t magic);

oe_result_t oe_private_key_init(
    oe_private_key_t* privateKey,
    const mbedtls_pk_context* pk,
    oe_copy_key copyKey,
    uint64_t magic);

void oe_private_key_release(oe_private_key_t* privateKey, uint64_t magic);

bool oe_public_key_is_valid(const oe_public_key_t* publicKey, uint64_t magic);

oe_result_t oe_public_key_init(
    oe_public_key_t* publicKey,
    const mbedtls_pk_context* pk,
    oe_copy_key copyKey,
    uint64_t magic);

void oe_public_key_release(oe_public_key_t* publicKey, uint64_t magic);

oe_result_t oe_private_key_read_pem(
    const uint8_t* pemData,
    size_t pemSize,
    oe_private_key_t* privateKey,
    mbedtls_pk_type_t keyType,
    uint64_t magic);

oe_result_t oe_private_key_write_pem(
    const oe_private_key_t* privateKey,
    uint8_t* pemData,
    size_t* pemSize,
    uint64_t magic);

oe_result_t oe_public_key_read_pem(
    const uint8_t* pemData,
    size_t pemSize,
    oe_public_key_t* publicKey,
    mbedtls_pk_type_t keyType,
    uint64_t magic);

oe_result_t oe_public_key_write_pem(
    const oe_public_key_t* publicKey,
    uint8_t* pemData,
    size_t* pemSize,
    uint64_t magic);

oe_result_t oe_private_key_free(oe_private_key_t* privateKey, uint64_t magic);

oe_result_t oe_public_key_free(oe_public_key_t* publicKey, uint64_t magic);

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

#endif /* _ENCLAVE_KEY_H */
