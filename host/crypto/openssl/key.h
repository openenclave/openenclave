// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _HOST_KEY_H
#define _HOST_KEY_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/crypto/hash.h>
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

typedef oe_result_t (
    *oe_private_key_write_pem_callback)(BIO* bio, EVP_PKEY* pkey);

bool oe_private_key_is_valid(const oe_private_key_t* impl, uint64_t magic);

bool oe_public_key_is_valid(const oe_public_key_t* impl, uint64_t magic);

void oe_public_key_init(
    oe_public_key_t* public_key,
    EVP_PKEY* pkey,
    uint64_t magic);

void oe_private_key_init(
    oe_private_key_t* private_key,
    EVP_PKEY* pkey,
    uint64_t magic);

oe_result_t oe_private_key_read_pem(
    const uint8_t* pem_data,
    size_t pem_size,
    oe_private_key_t* key,
    int key_type,
    uint64_t magic);

oe_result_t oe_public_key_read_pem(
    const uint8_t* pem_data,
    size_t pem_size,
    oe_public_key_t* key,
    int key_type,
    uint64_t magic);

oe_result_t oe_private_key_from_engine(
    const char* engine_id,
    const char* engine_load_path,
    const char* key_id,
    oe_private_key_t* key,
    int key_type,
    uint64_t magic);

oe_result_t oe_private_key_write_pem(
    const oe_private_key_t* private_key,
    uint8_t* data,
    size_t* size,
    oe_private_key_write_pem_callback private_key_write_pem_callback,
    uint64_t magic);

oe_result_t oe_public_key_write_pem(
    const oe_public_key_t* key,
    uint8_t* data,
    size_t* size,
    uint64_t magic);

oe_result_t oe_private_key_free(oe_private_key_t* key, uint64_t magic);

oe_result_t oe_public_key_free(oe_public_key_t* key, uint64_t magic);

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

#endif /* _HOST_KEY_H */
