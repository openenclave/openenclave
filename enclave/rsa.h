// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_RSA_H
#define _OE_ENCLAVE_RSA_H

#if !defined(OE_NEED_STDC_NAMES)
#define OE_NEED_STDC_NAMES
#define __UNDEF_OE_NEED_STDC_NAMES
#endif
#include <mbedtls/pk.h>
#if defined(__UNDEF_OE_NEED_STDC_NAMES)
#undef OE_NEED_STDC_NAMES
#undef __UNDEF_OE_NEED_STDC_NAMES
#endif

#include <openenclave/internal/rsa.h>

OE_INLINE bool oe_is_rsa_key(const mbedtls_pk_context* pk)
{
    return (pk->pk_info == mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
}

oe_result_t oe_rsa_public_key_init(
    oe_rsa_public_key_t* public_key,
    const mbedtls_pk_context* pk);

#endif /* _OE_ENCLAVE_RSA_H */
