// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <mbedtls/md.h>

#include <openenclave/internal/defs.h>
#include <openenclave/internal/hmac.h>
#include <openenclave/internal/raise.h>

typedef struct _oe_hmac_sha256_context_impl
{
    mbedtls_md_context_t ctx;
} oe_hmac_sha256_context_impl_t;

OE_STATIC_ASSERT(
    sizeof(oe_hmac_sha256_context_impl_t) <= sizeof(oe_hmac_sha256_context_t));

oe_result_t oe_hmac_sha256_init(
    oe_hmac_sha256_context_t* context,
    const uint8_t* key,
    size_t keysize)
{
    oe_result_t result = OE_UNEXPECTED;
    int mbedtls_result;
    oe_hmac_sha256_context_impl_t* impl =
        (oe_hmac_sha256_context_impl_t*)context;

    if (!context || !key)
        OE_RAISE(OE_INVALID_PARAMETER);

    mbedtls_md_init(&impl->ctx);
    mbedtls_result = mbedtls_md_setup(
        &impl->ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);

    if (mbedtls_result != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "mbedtls error: 0x%x", mbedtls_result);

    mbedtls_result = mbedtls_md_hmac_starts(&impl->ctx, key, keysize);
    if (mbedtls_result != 0)
    {
        mbedtls_md_free(&impl->ctx);
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "mbedtls error: 0x%x", mbedtls_result);
    }

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
    int res;

    if (!context || !data)
        OE_RAISE(OE_INVALID_PARAMETER);

    res = mbedtls_md_hmac_update(&impl->ctx, (const uint8_t*)data, size);
    if (res != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "mbedtls error: 0x%x", res);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_hmac_sha256_final(
    oe_hmac_sha256_context_t* context,
    OE_SHA256* sha256)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_hmac_sha256_context_impl_t* impl =
        (oe_hmac_sha256_context_impl_t*)context;
    int res;

    if (!context || !sha256)
        OE_RAISE(OE_INVALID_PARAMETER);

    res = mbedtls_md_hmac_finish(&impl->ctx, sha256->buf);
    if (res != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "mbedtls error: 0x%x", res);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_hmac_sha256_free(oe_hmac_sha256_context_t* context)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_hmac_sha256_context_impl_t* impl =
        (oe_hmac_sha256_context_impl_t*)context;

    if (!context)
        OE_RAISE(OE_INVALID_PARAMETER);

    mbedtls_md_free(&impl->ctx);
    result = OE_OK;

done:
    return result;
}
