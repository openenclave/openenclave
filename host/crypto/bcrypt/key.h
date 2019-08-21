// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _HOST_KEY_H
#define _HOST_KEY_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/crypto/hash.h>
#include "bcrypt.h"

typedef struct _oe_bcrypt_key
{
    uint64_t magic;
    BCRYPT_KEY_HANDLE handle;
} oe_private_key_t, oe_public_key_t, oe_bcrypt_key_t;

typedef struct _oe_bcrypt_padding_info
{
    uint32_t type;
    void* config;
} oe_bcrypt_padding_info_t;

typedef oe_result_t (*oe_bcrypt_decode_key_callback_t)(
    const BYTE* der_data,
    DWORD der_data_size,
    BCRYPT_KEY_HANDLE* key_handle);

/* Caller is expected to call LocalFree on der_data */
typedef oe_result_t (*oe_bcrypt_encode_key_callback_t)(
    const BCRYPT_KEY_HANDLE key_handle,
    BYTE** der_data,
    DWORD* der_data_size);

oe_result_t oe_bcrypt_decode_x509_public_key(
    const BYTE* der_data,
    DWORD der_data_size,
    BCRYPT_KEY_HANDLE* key_handle);

oe_result_t oe_bcrypt_encode_x509_public_key(
    const BCRYPT_KEY_HANDLE key_handle,
    LPSTR key_oid,
    BYTE** der_data,
    DWORD* der_data_size);

oe_result_t oe_bcrypt_export_key(
    const BCRYPT_KEY_HANDLE key_handle,
    LPCWSTR key_blob_type,
    BYTE** key_blob_data,
    ULONG* key_blob_size);

oe_result_t oe_bcrypt_get_public_key_info(
    const BCRYPT_KEY_HANDLE key_handle,
    LPSTR key_oid,
    PCERT_PUBLIC_KEY_INFO* key_info,
    DWORD* key_info_size);

oe_result_t oe_bcrypt_key_free(oe_bcrypt_key_t* key, uint64_t magic);

void oe_bcrypt_key_init(
    oe_bcrypt_key_t* key,
    BCRYPT_KEY_HANDLE* handle,
    uint64_t magic);

bool oe_bcrypt_key_is_valid(const oe_bcrypt_key_t* impl, uint64_t magic);

oe_result_t oe_bcrypt_key_get_blob(
    const oe_bcrypt_key_t* key,
    uint64_t key_magic,
    LPCWSTR blob_type,
    BYTE** blob_data,
    ULONG* blob_size);

oe_result_t oe_bcrypt_key_read_pem(
    const uint8_t* pem_data,
    size_t pem_size,
    uint64_t key_magic,
    oe_bcrypt_decode_key_callback_t decode_key,
    oe_bcrypt_key_t* key);

oe_result_t oe_bcrypt_key_write_pem(
    const oe_bcrypt_key_t* key,
    uint64_t key_magic,
    oe_bcrypt_encode_key_callback_t encode_key,
    uint8_t* pem_data,
    size_t* pem_size);

oe_result_t oe_private_key_sign(
    const oe_private_key_t* private_key,
    uint64_t key_magic,
    const oe_bcrypt_padding_info_t* padding_info,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size);

oe_result_t oe_public_key_verify(
    const oe_public_key_t* public_key,
    uint64_t key_magic,
    const oe_bcrypt_padding_info_t* padding_info,
    const void* hash_data,
    size_t hash_size,
    const uint8_t* signature,
    size_t signature_size);

#endif /* _HOST_KEY_H */
