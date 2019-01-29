// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_EC_H
#define _OE_ENCLAVE_EC_H

#if !defined(OE_NEED_STDC_NAMES)
#define OE_NEED_STDC_NAMES
#define __UNDEF_OE_NEED_STDC_NAMES
#endif
#include <mbedtls/pk.h>
#if defined(__UNDEF_OE_NEED_STDC_NAMES)
#undef OE_NEED_STDC_NAMES
#undef __UNDEF_OE_NEED_STDC_NAMES
#endif

#include <openenclave/internal/ec.h>

OE_INLINE bool oe_is_ec_key(const mbedtls_pk_context* pk)
{
    return (pk->pk_info == mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
}

oe_result_t oe_ec_public_key_init(
    oe_ec_public_key_t* public_key,
    const mbedtls_pk_context* pk);

oe_result_t oe_ec_private_key_init(
    oe_ec_private_key_t* private_key,
    const mbedtls_pk_context* pk);

#endif /* _OE_ENCLAVE_EC_H */
