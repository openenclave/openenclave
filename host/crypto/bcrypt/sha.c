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
    PBYTE hash_state;
    DWORD hash_state_size;
} oe_sha256_context_impl_t;

OE_STATIC_ASSERT(
    sizeof(oe_sha256_context_impl_t) <= sizeof(oe_sha256_context_t));

oe_result_t oe_sha256_init(oe_sha256_context_t* context)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sha256_context_impl_t* impl = (oe_sha256_context_impl_t*)context;

    if (!context)
        OE_RAISE(OE_INVALID_PARAMETER);

    NTSTATUS status;

#ifdef OE_WITH_EXPERIMENTAL_EEID
    /* oe_sha256_save and oe_sha256_restore require access to the internal hash
     * state, which is not exposed later, so we ask BCrypt to use a memory block
     * that we pre-allocate. */
    DWORD data_size = 0;

    /* Get required size for hash state object */
    status = BCryptGetProperty(
        BCRYPT_SHA256_ALG_HANDLE,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&impl->hash_state_size,
        sizeof(DWORD),
        &data_size,
        0);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "BCryptGetProperty failed (err=%#x)\n", status);

    /* Check that the hash state object has the expected size. If this ever
     * changes, BCRYPT_SHA256_STATE_OFFSET and BCRYPT_SHA256_COUNT_OFFSET need
     * to be adjusted. */
    if (impl->hash_state_size != 326)
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR,
            "BCrypt SHA256 state has unexpected size (%d).\n",
            impl->hash_state_size);

    impl->hash_state = malloc(impl->hash_state_size);
    if (!impl->hash_state)
        OE_RAISE(OE_OUT_OF_MEMORY);
#else
    impl->hash_state = NULL;
    impl->hash_state_size = 0;
#endif

    status = BCryptCreateHash(
        BCRYPT_SHA256_ALG_HANDLE,
        &impl->handle,
        impl->hash_state,
        impl->hash_state_size,
        NULL,
        0,
        0);

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

#ifdef OE_WITH_EXPERIMENTAL_EEID

/* This is very brittle; these offsets into the state object may change
 * without notice. Since bcrypt doesn't provide this information elsewhere,
 * the only solution I can think of is to use a different library for
 * SHA256. */
#define BCRYPT_SHA256_STATE_OFFSET 68
#define BCRYPT_SHA256_COUNT_OFFSET 48

oe_result_t oe_sha256_save(
    const oe_sha256_context_t* context,
    uint32_t* internal_hash,
    uint32_t* hashed_count)
{
    oe_result_t result = OE_INVALID_PARAMETER;
    oe_sha256_context_impl_t* impl = (oe_sha256_context_impl_t*)context;

    if (!context || !internal_hash || !hashed_count)
        OE_RAISE(OE_INVALID_PARAMETER);

    uint32_t* state = (uint32_t*)impl->hash_state;
    for (size_t i = 0; i < 8; i++)
        internal_hash[i] = state[BCRYPT_SHA256_STATE_OFFSET + i];

    uint32_t low = state[BCRYPT_SHA256_COUNT_OFFSET];
    uint32_t high = state[BCRYPT_SHA256_COUNT_OFFSET + 1];

    hashed_count[0] = low * 8;
    hashed_count[1] = high * 8 + (low >> 29);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sha256_restore(
    oe_sha256_context_t* context,
    const uint32_t* internal_hash,
    const uint32_t* hashed_count)
{
    oe_result_t result = OE_INVALID_PARAMETER;
    oe_sha256_context_impl_t* impl = (oe_sha256_context_impl_t*)context;

    if (!context || !internal_hash || !hashed_count)
        OE_RAISE(OE_INVALID_PARAMETER);

    oe_sha256_init(context);

    uint32_t* state = (uint32_t*)impl->hash_state;
    for (size_t i = 0; i < 8; i++)
        state[BCRYPT_SHA256_STATE_OFFSET + i] = internal_hash[i];

    uint64_t NB = ((((uint64_t)hashed_count[1]) << 32) + hashed_count[0]) / 8;
    state[BCRYPT_SHA256_COUNT_OFFSET] = NB & 0xFFFFFFFF;
    state[BCRYPT_SHA256_COUNT_OFFSET + 1] = ((uint32_t)(NB >> 32)) & 0xFFFFFFFF;

    result = OE_OK;

done:
    return result;
}
#endif
