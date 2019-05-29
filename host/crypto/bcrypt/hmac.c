// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "bcrypt.h"

#include <openenclave/internal/defs.h>
#include <openenclave/internal/hmac.h>
#include <openenclave/internal/raise.h>

typedef struct _oe_hmac_sha256_context_impl
{
    BCRYPT_HASH_HANDLE handle;
} oe_hmac_sha256_context_impl_t;

OE_STATIC_ASSERT(
    sizeof(oe_hmac_sha256_context_impl_t) <= sizeof(oe_hmac_sha256_context_t));

oe_result_t oe_hmac_sha256_init(
    oe_hmac_sha256_context_t* context,
    const uint8_t* key,
    size_t keysize)
{
    oe_result_t result = OE_UNEXPECTED;
    BCRYPT_HASH_HANDLE handle = NULL;
    NTSTATUS status;

    if (!context || !key || keysize > OE_UINT32_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    status = BCryptCreateHash(
        BCRYPT_HMAC_SHA256_ALG_HANDLE,
        &handle,
        NULL,
        0,
        (PUCHAR)key,
        (ULONG)keysize,
        0);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE(OE_CRYPTO_ERROR);

    ((oe_hmac_sha256_context_impl_t*)context)->handle = handle;
    result = OE_OK;

done:
    return result;
}

oe_result_t oe_hmac_sha256_update(
    oe_hmac_sha256_context_t* context,
    const void* data,
    size_t size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_hmac_sha256_context_impl_t* impl =
        (oe_hmac_sha256_context_impl_t*)context;
    NTSTATUS status;

    if (!context || !data || size > OE_UINT32_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    status = BCryptHashData(impl->handle, (PUCHAR)data, (ULONG)size, 0);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE(OE_CRYPTO_ERROR);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_hmac_sha256_final(
    oe_hmac_sha256_context_t* context,
    OE_SHA256* sha256)
{
    oe_result_t result = OE_UNEXPECTED;
    NTSTATUS status;
    oe_hmac_sha256_context_impl_t* impl =
        (oe_hmac_sha256_context_impl_t*)context;

    if (!context || !sha256)
        OE_RAISE(OE_INVALID_PARAMETER);

    status =
        BCryptFinishHash(impl->handle, sha256->buf, sizeof(sha256->buf), 0);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE(OE_CRYPTO_ERROR);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_hmac_sha256_free(oe_hmac_sha256_context_t* context)
{
    oe_result_t result = OE_UNEXPECTED;
    NTSTATUS status;
    oe_hmac_sha256_context_impl_t* impl =
        (oe_hmac_sha256_context_impl_t*)context;

    if (!context)
        OE_RAISE(OE_INVALID_PARAMETER);

    status = BCryptDestroyHash(impl->handle);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE(OE_CRYPTO_ERROR);

    result = OE_OK;

done:
    return result;
}
