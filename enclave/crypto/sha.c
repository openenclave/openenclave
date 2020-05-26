// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <mbedtls/sha256.h>

#include <openenclave/bits/types.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>

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
    int rc = 0;

    if (!context)
        OE_RAISE(OE_INVALID_PARAMETER);

    mbedtls_sha256_init(&impl->ctx);

    rc = mbedtls_sha256_starts_ret(&impl->ctx, 0);
    if (rc != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "rc = 0x%x\n", rc);

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
    int rc = 0;

    if (!context || !data)
        OE_RAISE(OE_INVALID_PARAMETER);

    rc = mbedtls_sha256_update_ret(&impl->ctx, data, size);
    if (rc != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "rc = 0x%x\n", rc);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sha256_final(oe_sha256_context_t* context, OE_SHA256* sha256)
{
    oe_result_t result = OE_INVALID_PARAMETER;
    oe_sha256_context_impl_t* impl = (oe_sha256_context_impl_t*)context;
    int rc = 0;

    if (!context || !sha256)
        OE_RAISE(OE_INVALID_PARAMETER);

    rc = mbedtls_sha256_finish_ret(&impl->ctx, sha256->buf);
    if (rc != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "rc = 0x%x\n", rc);

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

    if (!context || !internal_hash || !num_hashed)
        OE_RAISE(OE_INVALID_PARAMETER);

    oe_sha256_context_impl_t* impl = (oe_sha256_context_impl_t*)context;

    for (size_t i = 0; i < 8; i++)
        internal_hash[i] = impl->ctx.state[i];

    num_hashed[0] = impl->ctx.total[0] * 8;
    num_hashed[1] = (impl->ctx.total[1] * 8) + (impl->ctx.total[0] >> 29);

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

    if (!context || !internal_hash || !num_hashed)
        OE_RAISE(OE_INVALID_PARAMETER);

    oe_sha256_context_impl_t* impl = (oe_sha256_context_impl_t*)context;
    oe_sha256_init(context);

    for (size_t i = 0; i < 8; i++)
        impl->ctx.state[i] = internal_hash[i];

    uint64_t NB = ((((uint64_t)num_hashed[1]) << 32) + num_hashed[0]) / 8;
    impl->ctx.total[0] = NB & 0xFFFFFFFF;
    impl->ctx.total[1] = (NB >> 32) & 0xFFFFFFFF;

    result = OE_OK;

done:
    return result;
}
#endif
