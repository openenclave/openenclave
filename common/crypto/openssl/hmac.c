// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/crypto/hmac.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>
#include <openssl/hmac.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
typedef struct _oe_hmac_sha256_context_impl
{
    HMAC_CTX* ctx;
} oe_hmac_sha256_context_impl_t;
#else
typedef struct _oe_hmac_sha256_context_impl
{
    EVP_MAC_CTX* ctx;
} oe_hmac_sha256_context_impl_t;
#endif

OE_STATIC_ASSERT(
    sizeof(oe_hmac_sha256_context_impl_t) <= sizeof(oe_hmac_sha256_context_t));

#if OPENSSL_VERSION_NUMBER < 0x30000000L
static void _free_hmac_ctx(HMAC_CTX* ctx)
{
    if (!ctx)
        return;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_cleanup(ctx);
    free(ctx);
#else
    HMAC_CTX_free(ctx);
#endif
}
#else
static void _free_hmac_ctx(EVP_MAC_CTX* ctx)
{
    if (!ctx)
        return;

    EVP_MAC_CTX_free(ctx);
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
oe_result_t oe_hmac_sha256_init(
    oe_hmac_sha256_context_t* context,
    const uint8_t* key,
    size_t keysize)
{
    oe_result_t result = OE_UNEXPECTED;
    HMAC_CTX* ctx = NULL;
    int openssl_result;

    if (!context || !key || keysize > OE_INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ctx = (HMAC_CTX*)malloc(sizeof(*ctx));
    if (ctx == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    HMAC_CTX_init(ctx);
#else
    ctx = HMAC_CTX_new();
    if (ctx == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);
#endif

    openssl_result =
        HMAC_Init_ex(ctx, (const void*)key, (int)keysize, EVP_sha256(), NULL);

    if (openssl_result == 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    ((oe_hmac_sha256_context_impl_t*)context)->ctx = ctx;
    ctx = NULL;
    result = OE_OK;

done:
    if (ctx != NULL)
        _free_hmac_ctx(ctx);

    return result;
}
#else
oe_result_t oe_hmac_sha256_init(
    oe_hmac_sha256_context_t* context,
    const uint8_t* key,
    size_t keysize)
{
    oe_result_t result = OE_UNEXPECTED;
    EVP_MAC_CTX* ctx = NULL;
    EVP_MAC* mac = NULL;
    OSSL_PARAM params[3];

    if (!context || !key || keysize > OE_INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL);

    if (!mac)
        OE_RAISE(OE_CRYPTO_ERROR);

    ctx = EVP_MAC_CTX_new(mac);

    if (ctx == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_MAC_PARAM_KEY, (void*)key, keysize);
    params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_MAC_PARAM_DIGEST, OSSL_DIGEST_NAME_SHA2_256, 0);
    params[2] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_init(ctx, NULL, 0, params))
        OE_RAISE(OE_CRYPTO_ERROR);

    ((oe_hmac_sha256_context_impl_t*)context)->ctx = ctx;
    ctx = NULL;
    result = OE_OK;

done:
    if (ctx != NULL)
        _free_hmac_ctx(ctx);
    if (mac)
        EVP_MAC_free(mac);

    return result;
}
#endif
#if OPENSSL_VERSION_NUMBER < 0x30000000L
oe_result_t oe_hmac_sha256_update(
    oe_hmac_sha256_context_t* context,
    const void* data,
    size_t size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_hmac_sha256_context_impl_t* impl =
        (oe_hmac_sha256_context_impl_t*)context;

    if (!context || !data || size > OE_INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (HMAC_Update(impl->ctx, (const uint8_t*)data, size) == 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    result = OE_OK;

done:
    return result;
}
#else
oe_result_t oe_hmac_sha256_update(
    oe_hmac_sha256_context_t* context,
    const void* data,
    size_t size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_hmac_sha256_context_impl_t* impl =
        (oe_hmac_sha256_context_impl_t*)context;

    if (!context || !data || size > OE_INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (EVP_MAC_update(impl->ctx, (const uint8_t*)data, size) == 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    result = OE_OK;

done:
    return result;
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
oe_result_t oe_hmac_sha256_final(
    oe_hmac_sha256_context_t* context,
    OE_SHA256* sha256)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_hmac_sha256_context_impl_t* impl =
        (oe_hmac_sha256_context_impl_t*)context;
    unsigned int hmac_size;

    if (!context || !sha256)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (HMAC_Final(impl->ctx, sha256->buf, &hmac_size) == 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (hmac_size != sizeof(sha256->buf))
        OE_RAISE(OE_CRYPTO_ERROR);

    result = OE_OK;

done:
    return result;
}
#else
oe_result_t oe_hmac_sha256_final(
    oe_hmac_sha256_context_t* context,
    OE_SHA256* sha256)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_hmac_sha256_context_impl_t* impl =
        (oe_hmac_sha256_context_impl_t*)context;
    size_t hmac_size = 0;

    if (!context || !sha256)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (EVP_MAC_final(impl->ctx, sha256->buf, &hmac_size, sizeof(OE_SHA256)) ==
        0)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (hmac_size != sizeof(sha256->buf))
        OE_RAISE(OE_CRYPTO_ERROR);

    result = OE_OK;

done:
    return result;
}
#endif
oe_result_t oe_hmac_sha256_free(oe_hmac_sha256_context_t* context)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_hmac_sha256_context_impl_t* impl =
        (oe_hmac_sha256_context_impl_t*)context;

    if (!context)
        OE_RAISE(OE_INVALID_PARAMETER);

    _free_hmac_ctx(impl->ctx);
    result = OE_OK;

done:
    return result;
}
