// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <mbedtls/sha256.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sha.h>

typedef struct _OE_SHA256ContextImpl
{
    mbedtls_sha256_context ctx;
} OE_SHA256ContextImpl;

OE_STATIC_ASSERT(sizeof(OE_SHA256ContextImpl) <= sizeof(OE_SHA256Context));

OE_Result OE_SHA256Init(OE_SHA256Context* context)
{
    OE_Result result = OE_UNEXPECTED;
    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

    if (!context)
        OE_RAISE(OE_INVALID_PARAMETER);

    mbedtls_sha256_init(&impl->ctx);

    mbedtls_sha256_starts(&impl->ctx, 0);

    result = OE_OK;

done:
    return result;
}

OE_Result OE_SHA256Update(
    OE_SHA256Context* context,
    const void* data,
    size_t size)
{
    OE_Result result = OE_INVALID_PARAMETER;
    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

    if (!context || !data)
        OE_RAISE(OE_INVALID_PARAMETER);

    mbedtls_sha256_update(&impl->ctx, data, size);

    result = OE_OK;

done:
    return result;
}

OE_Result OE_SHA256Final(OE_SHA256Context* context, OE_SHA256* sha256)
{
    OE_Result result = OE_INVALID_PARAMETER;
    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

    if (!context || !sha256)
        OE_RAISE(OE_INVALID_PARAMETER);

    mbedtls_sha256_finish(&impl->ctx, sha256->buf);

    result = OE_OK;

done:
    return result;
}
