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

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#else
#include <openenclave/host.h>
#endif

typedef struct _OE_SHA256ContextImpl
{
#if defined(__linux__)
    SHA256_CTX ctx;
#elif defined(_WIN32)
    BCRYPT_HASH_HANDLE handle;
#endif
} OE_SHA256ContextImpl;

OE_STATIC_ASSERT(sizeof(OE_SHA256ContextImpl) <= sizeof(OE_SHA256Context));

void OE_SHA256Init(OE_SHA256Context* context)
{
    if (!context)
        return;

    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

#if defined(__linux__)
    SHA256_Init(&impl->ctx);
#elif defined(_WIN32)
    BCryptCreateHash(
        BCRYPT_SHA256_ALG_HANDLE, &impl->handle, NULL, 0, NULL, 0, 0);
#endif
}

void OE_SHA256Update(OE_SHA256Context* context, const void* data, size_t size)
{
    if (!context)
        return;

    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

#if defined(__linux__)
    SHA256_Update(&impl->ctx, data, size);
#elif defined(_WIN32)
    BCryptHashData(impl->handle, (void*)data, (ULONG)size, 0);
#endif
}

void OE_SHA256Final(OE_SHA256Context* context, OE_SHA256* sha256)
{
    if (!context)
        return;

    OE_SHA256ContextImpl* impl = (OE_SHA256ContextImpl*)context;

#if defined(__linux__)
    SHA256_Final(sha256->buf, &impl->ctx);
#elif defined(_WIN32)
    BCryptFinishHash(impl->handle, sha256->buf, sizeof(OE_SHA256), 0);
#endif
}
