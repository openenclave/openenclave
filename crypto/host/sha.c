// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdio.h>
#include <string.h>

#if defined(__linux__)
#include <openssl/sha.h>
#elif defined(_WIN32)
#include <Windows.h>
#include <bcrypt.h>
#endif

#include <openenclave/host.h>

typedef struct _OE_SHA256ContextImpl
{
#if defined(__linux__)
    SHA256_CTX ctx;
#elif defined(_WIN32)
    BCRYPT_HASH_HANDLE handle;
#endif
} OE_SHA256ContextImpl;

OE_STATIC_ASSERT(sizeof(OE_SHA256ContextImpl) <= sizeof(OE_SHA256Context));

OE_Result OE_SHA256Init(OE_SHA256Context* context)
{
    OE_Result result = OE_UNEXPECTED;
    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

    if (!context)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

#if defined(__linux__)
    if (!SHA256_Init(&impl->ctx))
    {
        result = OE_FAILURE;
        goto done;
    }
#elif defined(_WIN32)
    if (BCryptCreateHash(
            BCRYPT_SHA256_ALG_HANDLE, &impl->handle, NULL, 0, NULL, 0, 0) !=
        STATUS_SUCCESS)
    {
        result = OE_FAILURE;
        goto done;
    }
#endif

    result = OE_OK;

done:
    return result;
}

OE_Result OE_SHA256Update(
    OE_SHA256Context* context,
    const void* data,
    size_t size)
{
    OE_Result result = OE_UNEXPECTED;
    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

    if (!context)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

#if defined(__linux__)
    if (!SHA256_Update(&impl->ctx, data, size))
    {
        result = OE_FAILURE;
        goto done;
    }
#elif defined(_WIN32)
    if (BCryptHashData(impl->handle, (void*)data, (ULONG)size, 0) !=
        STATUS_SUCCESS)
    {
        result = OE_FAILURE;
        goto done;
    }
#endif

    result = OE_OK;

done:
    return result;
}

OE_Result OE_SHA256Final(OE_SHA256Context* context, OE_SHA256* sha256)
{
    OE_Result result = OE_UNEXPECTED;
    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

    if (!context)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

#if defined(__linux__)
    if (!SHA256_Final(sha256->buf, &impl->ctx))
    {
        result = OE_FAILURE;
        goto done;
    }
#elif defined(_WIN32)
    if (BCryptFinishHash(impl->handle, sha256->buf, sizeof(OE_SHA256), 0) !=
        STATUS_SUCCESS)
    {
        result = OE_FAILURE;
        goto done;
    }
#endif

    result = OE_OK;

done:
    return result;
}
