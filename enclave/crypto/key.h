// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVE_KEY_H
#define _ENCLAVE_KEY_H

/* Nest mbedtls header includes with required corelibc defines */
// clang-format off
#include "mbedtls_corelibc_defs.h"
#include <mbedtls/pk.h>
#include "mbedtls_corelibc_undef.h"
// clang-format on

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
    bool copy_private_fields);

bool oe_private_key_is_valid(
    const oe_private_key_t* private_key,
    uint64_t magic);

oe_result_t oe_private_key_init(
    oe_private_key_t* private_key,
    const mbedtls_pk_context* pk,
    oe_copy_key copy_key,
    uint64_t magic);

void oe_private_key_release(oe_private_key_t* private_key, uint64_t magic);

bool oe_public_key_is_valid(const oe_public_key_t* public_key, uint64_t magic);

oe_result_t oe_public_key_init(
    oe_public_key_t* public_key,
    const mbedtls_pk_context* pk,
    oe_copy_key copy_key,
    uint64_t magic);

void oe_public_key_release(oe_public_key_t* public_key, uint64_t magic);

oe_result_t oe_private_key_read_pem(
    const uint8_t* pem_data,
    size_t pem_size,
    oe_private_key_t* private_key,
    mbedtls_pk_type_t key_type,
    uint64_t magic);

oe_result_t oe_private_key_write_pem(
    const oe_private_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_size,
    uint64_t magic);

oe_result_t oe_public_key_read_pem(
    const uint8_t* pem_data,
    size_t pem_size,
    oe_public_key_t* public_key,
    mbedtls_pk_type_t key_type,
    uint64_t magic);

oe_result_t oe_public_key_write_pem(
    const oe_public_key_t* public_key,
    uint8_t* pem_data,
    size_t* pem_size,
    uint64_t magic);

oe_result_t oe_private_key_free(oe_private_key_t* private_key, uint64_t magic);

oe_result_t oe_public_key_free(oe_public_key_t* public_key, uint64_t magic);

oe_result_t oe_private_key_sign(
    const oe_private_key_t* private_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size,
    uint64_t magic);

oe_result_t oe_public_key_verify(
    const oe_public_key_t* public_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    const uint8_t* signature,
    size_t signature_size,
    uint64_t magic);

#endif /* _ENCLAVE_KEY_H */
