// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_CRYPTO_PEM_H
#define _OE_HOST_CRYPTO_PEM_H

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

typedef enum _oe_pem_header
{
    OE_PEM_HEADER_CERTIFICATE = 0,
    OE_PEM_HEADER_PUBLIC_KEY = 1,
    OE_PEM_HEADER_PRIVATE_KEY = 2,
    OE_PEM_HEADER_RSA_PRIVATE_KEY = 3,
    OE_PEM_HEADER_EC_PRIVATE_KEY = 4,
    __OE_PEM_HEADER_MAX = OE_ENUM_MAX,
} oe_pem_header_t;

oe_result_t oe_bcrypt_pem_to_der(
    const uint8_t* pem_data,
    size_t pem_size,
    BYTE** der_data,
    DWORD* der_data_size);

oe_result_t oe_bcrypt_der_to_pem(
    oe_pem_header_t pem_type,
    const BYTE* der_data,
    DWORD der_data_size,
    uint8_t** pem_data,
    size_t* pem_size);

oe_result_t oe_get_next_pem_cert(
    const void** pem_read_pos,
    size_t* pem_bytes_remaining,
    char** pem_cert,
    size_t* pem_cert_size);

#endif /* _OE_HOST_CRYPTO_PEM_H */
