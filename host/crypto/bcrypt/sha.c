// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>
#include <stdio.h>
#include <string.h>
#include "bcrypt.h"

typedef struct _oe_sha256_context_impl
{
    BCRYPT_HASH_HANDLE handle;
} oe_sha256_context_impl_t;

OE_STATIC_ASSERT(
    sizeof(oe_sha256_context_impl_t) <= sizeof(oe_sha256_context_t));

oe_result_t oe_sha256_init(oe_sha256_context_t* context)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sha256_context_impl_t* impl = (oe_sha256_context_impl_t*)context;

    if (!context)
        OE_RAISE(OE_INVALID_PARAMETER);

    NTSTATUS status = BCryptCreateHash(
        BCRYPT_SHA256_ALG_HANDLE, &impl->handle, NULL, 0, NULL, 0, 0);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "BCryptCreateHash failed (err=%#x)\n", status);

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

    NTSTATUS status = BCryptHashData(impl->handle, (void*)data, (ULONG)size, 0);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "BCryptHashData failed (err=%#x)\n", status);

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

    NTSTATUS status =
        BCryptFinishHash(impl->handle, sha256->buf, sizeof(OE_SHA256), 0);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "BCryptFinishHash failed (err=%#x)\n", status);

    result = OE_OK;

done:
    return result;
}
