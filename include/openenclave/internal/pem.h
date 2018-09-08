// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_PEM_H
#define _OE_PEM_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

#define OE_PEM_BEGIN_CERTIFICATE "-----BEGIN CERTIFICATE-----"
#define OE_PEM_END_CERTIFICATE "-----END CERTIFICATE-----"

#define OE_PEM_BEGIN_PUBLIC_KEY "-----BEGIN PUBLIC KEY-----"
#define OE_PEM_END_PUBLIC_KEY "-----END PUBLIC KEY-----"

#define OE_PEM_BEGIN_PRIVATE_KEY "-----BEGIN PRIVATE KEY-----"
#define OE_PEM_END_PRIVATE_KEY "-----END PRIVATE KEY-----"

#define OE_PEM_BEGIN_RSA_PRIVATE_KEY "-----BEGIN RSA PRIVATE KEY-----"
#define OE_PEM_END_RSA_PRIVATE_KEY "-----END RSA PRIVATE KEY-----"

#define OE_PEM_BEGIN_EC_PRIVATE_KEY "-----BEGIN EC PRIVATE KEY-----"
#define OE_PEM_END_EC_PRIVATE_KEY "-----END EC PRIVATE KEY-----"

#define OE_PEM_BEGIN_X509_CRL "-----BEGIN X509 CRL-----"
#define OE_PEM_END_X509_CRL "-----END X509 CRL-----"

typedef enum _oe_pem_type {
    OE_PEM_TYPE_CERTIFICATE,
    OE_PEM_TYPE_PUBLIC_KEY,
    OE_PEM_TYPE_PRIVATE_KEY,
    OE_PEM_TYPE_RSA_PUBLIC_KEY,
    OE_PEM_TYPE_EC_PRIVATE_KEY,
    OE_PEM_TYPE_X509_CRL,
} oe_pem_type_t;

oe_result_t oe_der_to_pem(
    const uint8_t* der,
    size_t der_size,
    oe_pem_type_t type,
    uint8_t* pem,
    size_t* pem_size);

OE_EXTERNC_END

#endif /* _OE_PEM_H */
