// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(__linux__)
#include <openssl/sha.h>
#elif defined(_WIN32)
#include "bcrypt/bcrypt.h"
#endif

#include <openenclave/host.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sha.h>
#include <stdio.h>
#include <string.h>

typedef struct _oe_sha256_context_impl
{
#if defined(__linux__)
    SHA256_CTX ctx;
#elif defined(_WIN32)
    BCRYPT_HASH_HANDLE handle;
#endif
} oe_sha256_context_impl_t;

OE_STATIC_ASSERT(
    sizeof(oe_sha256_context_impl_t) <= sizeof(oe_sha256_context_t));

oe_result_t oe_sha256_init(oe_sha256_context_t* context)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sha256_context_impl_t* impl = (oe_sha256_context_impl_t*)context;

    if (!context)
        OE_RAISE(OE_INVALID_PARAMETER);

#if defined(__linux__)
    if (!SHA256_Init(&impl->ctx))
        OE_RAISE(OE_FAILURE);
#elif defined(_WIN32)
    if (BCryptCreateHash(
            BCRYPT_SHA256_ALG_HANDLE, &impl->handle, NULL, 0, NULL, 0, 0) !=
        STATUS_SUCCESS)
    {
        OE_RAISE(OE_FAILURE);
    }
#endif

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sha256_update(
    oe_sha256_context_t* context,
    const void* data,
    size_t size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sha256_context_impl_t* impl = (oe_sha256_context_impl_t*)context;

    if (!context)
        OE_RAISE(OE_INVALID_PARAMETER);

#if defined(__linux__)
    if (!SHA256_Update(&impl->ctx, data, size))
        OE_RAISE(OE_FAILURE);
#elif defined(_WIN32)
    if (BCryptHashData(impl->handle, (void*)data, (ULONG)size, 0) !=
        STATUS_SUCCESS)
    {
        OE_RAISE(OE_FAILURE);
    }
#endif

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sha256_final(oe_sha256_context_t* context, OE_SHA256* sha256)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sha256_context_impl_t* impl = (oe_sha256_context_impl_t*)context;

    if (!context)
        OE_RAISE(OE_INVALID_PARAMETER);

#if defined(__linux__)
    if (!SHA256_Final(sha256->buf, &impl->ctx))
        OE_RAISE(OE_FAILURE);
#elif defined(_WIN32)
    if (BCryptFinishHash(impl->handle, sha256->buf, sizeof(OE_SHA256), 0) !=
        STATUS_SUCCESS)
    {
        OE_RAISE(OE_FAILURE);
    }
#endif

    result = OE_OK;

done:
    return result;
}
