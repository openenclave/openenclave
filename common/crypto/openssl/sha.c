// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

typedef struct _oe_sha256_context_impl
{
    SHA256_CTX ctx;
} oe_sha256_context_impl_t;

OE_STATIC_ASSERT(
    sizeof(oe_sha256_context_impl_t) <= sizeof(oe_sha256_context_t));

oe_result_t oe_sha256_init(oe_sha256_context_t* context)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sha256_context_impl_t* impl = (oe_sha256_context_impl_t*)context;

    if (!context)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!SHA256_Init(&impl->ctx))
        OE_RAISE(OE_CRYPTO_ERROR);

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

    if (!SHA256_Update(&impl->ctx, data, size))
        OE_RAISE(OE_CRYPTO_ERROR);

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

    if (!SHA256_Final(sha256->buf, &impl->ctx))
        OE_RAISE(OE_CRYPTO_ERROR);

    result = OE_OK;

done:
    return result;
}

#ifdef OE_WITH_EXPERIMENTAL_EEID
oe_result_t oe_sha256_save(
    const oe_sha256_context_t* context,
    uint32_t* internal_hash,
    uint32_t* num_hashed)
{
    oe_result_t result = OE_INVALID_PARAMETER;
    oe_sha256_context_impl_t* impl = (oe_sha256_context_impl_t*)context;

    if (!context || !internal_hash || !num_hashed)
        OE_RAISE(OE_INVALID_PARAMETER);

    for (size_t i = 0; i < 8; i++)
        internal_hash[i] = impl->ctx.h[i];

    num_hashed[0] = impl->ctx.Nl;
    num_hashed[1] = impl->ctx.Nh;

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sha256_restore(
    oe_sha256_context_t* context,
    const uint32_t* internal_hash,
    const uint32_t* num_hashed)
{
    oe_result_t result = OE_INVALID_PARAMETER;
    oe_sha256_context_impl_t* impl = (oe_sha256_context_impl_t*)context;

    if (!context || !internal_hash || !num_hashed)
        OE_RAISE(OE_INVALID_PARAMETER);

    oe_sha256_init(context);

    for (size_t i = 0; i < 8; i++)
        impl->ctx.h[i] = internal_hash[i];

    impl->ctx.Nl = num_hashed[0];
    impl->ctx.Nh = num_hashed[1];

    result = OE_OK;

done:
    return result;
}
#endif
