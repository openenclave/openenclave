// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if !defined(OE_NEED_STDC_NAMES)
#define OE_NEED_STDC_NAMES
#define __UNDEF_OE_NEED_STDC_NAMES
#endif
#include <mbedtls/sha256.h>
#if defined(__UNDEF_OE_NEED_STDC_NAMES)
#undef OE_NEED_STDC_NAMES
#undef __UNDEF_OE_NEED_STDC_NAMES
#endif

#include <openenclave/bits/types.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sha.h>

typedef struct _oe_sha256_context_impl
{
    mbedtls_sha256_context ctx;
} oe_sha256_context_impl_t;

OE_STATIC_ASSERT(
    sizeof(oe_sha256_context_impl_t) <= sizeof(oe_sha256_context_t));

oe_result_t oe_sha256_init(oe_sha256_context_t* context)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sha256_context_impl_t* impl = (oe_sha256_context_impl_t*)context;

    if (!context)
        OE_RAISE(OE_INVALID_PARAMETER);

    mbedtls_sha256_init(&impl->ctx);

    mbedtls_sha256_starts_ret(&impl->ctx, 0);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sha256_update(
    oe_sha256_context_t* context,
    const void* data,
    size_t size)
{
    oe_result_t result = OE_INVALID_PARAMETER;
    oe_sha256_context_impl_t* impl = (oe_sha256_context_impl_t*)context;

    if (!context || !data)
        OE_RAISE(OE_INVALID_PARAMETER);

    mbedtls_sha256_update_ret(&impl->ctx, data, size);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sha256_final(oe_sha256_context_t* context, OE_SHA256* sha256)
{
    oe_result_t result = OE_INVALID_PARAMETER;
    oe_sha256_context_impl_t* impl = (oe_sha256_context_impl_t*)context;

    if (!context || !sha256)
        OE_RAISE(OE_INVALID_PARAMETER);

    mbedtls_sha256_finish_ret(&impl->ctx, sha256->buf);

    result = OE_OK;

done:
    return result;
}
