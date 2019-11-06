// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_RSA_H
#define _OE_ENCLAVE_RSA_H

#include <mbedtls/pk.h>

#include <openenclave/internal/rsa.h>

OE_INLINE bool oe_is_rsa_key(const mbedtls_pk_context* pk)
{
    return (pk->pk_info == mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
}

oe_result_t oe_rsa_public_key_init(
    oe_rsa_public_key_t* public_key,
    const mbedtls_pk_context* pk);

#endif /* _OE_ENCLAVE_RSA_H */
