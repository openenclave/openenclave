// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/result.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/hmac.h>
#include <openenclave/internal/kdf.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sha.h>
#include <openenclave/internal/utils.h>

#include "common.h"

static inline size_t _min(size_t x, size_t y)
{
    return (x < y) ? x : y;
}

static inline uint32_t _to_big_endian(uint32_t x)
{
    return ((x & 0xFF000000U) >> 24) | ((x & 0x00FF0000U) >> 8) |
           ((x & 0x0000FF00U) << 8) | ((x & 0x000000FFU) << 24);
}

static oe_result_t kdf_hmac_sha256_ctr(
    const uint8_t* key,
    size_t key_size,
    const uint8_t* fixed_data,
    uint8_t fixed_data_size,
    uint8_t* derived_key,
    size_t derived_key_size)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t derived_key_size_rounded;
    oe_hmac_sha256_context_t ctx;
    OE_SHA256 sha256;
    size_t iters;
    uint32_t ctr;

    if (!key || !derived_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    /*
     * Algorithm specified in NIST SP800-108. Essentially, for
     * i = 1 to CEIL(derived_key_size / hash_length), calculate
     * HMAC-SHA256(key, i || fixed_data) and concatenate the results.
     */
    OE_CHECK(
        oe_safe_add_sizet(
            derived_key_size, OE_SHA256_SIZE - 1, &derived_key_size_rounded));

    iters = derived_key_size_rounded / OE_SHA256_SIZE;

    /* NIST specifies that the counter must be at most 2^32 - 1. */
    if (iters > OE_UINT32_MAX)
        OE_RAISE(OE_CONSTRAINT_FAILED);

    for (size_t i = 1; i <= iters; i++)
    {
        size_t bytes_to_copy = _min(derived_key_size, OE_SHA256_SIZE);

        /* Counter must be in big endian. Assume we're little endian. */
        ctr = _to_big_endian((uint32_t)i);

        OE_CHECK(oe_hmac_sha256_init(&ctx, key, key_size));
        OE_CHECK(oe_hmac_sha256_update(&ctx, (uint8_t*)&ctr, sizeof(ctr)));
        if (fixed_data)
            OE_CHECK(oe_hmac_sha256_update(&ctx, fixed_data, fixed_data_size));
        OE_CHECK(oe_hmac_sha256_final(&ctx, &sha256));
        OE_CHECK(oe_hmac_sha256_free(&ctx));

        OE_CHECK(
            oe_memcpy_s(derived_key, bytes_to_copy, sha256.buf, bytes_to_copy));

        derived_key += bytes_to_copy;
        derived_key_size -= bytes_to_copy;
    }

    result = OE_OK;

done:
    oe_secure_zero_fill(sha256.buf, sizeof(sha256.buf));
    return result;
}

oe_result_t oe_kdf_create_fixed_data(
    const uint8_t* label,
    size_t label_size,
    const uint8_t* context,
    size_t context_size,
    size_t output_key_size,
    uint8_t** fixed_data,
    size_t* fixed_data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* data = NULL;
    size_t data_size = 0;
    uint8_t* data_cur = NULL;
    size_t data_size_cur = 0;
    uint32_t key_bits;

    if (!fixed_data || !fixed_data_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* The output key length is at most 2^32 - 1 in bits. */
    if (output_key_size > OE_UINT32_MAX / 8)
        OE_RAISE(OE_CONSTRAINT_FAILED);

    if (label == NULL)
        label_size = 0;

    if (context == NULL)
        context_size = 0;

    /* The fixed data is label || 0x00 || Context || key_bits */
    OE_CHECK(oe_safe_add_sizet(label_size, context_size, &data_size));

    /* The +5 is 1 byte for 0x00 and 4 bytes for key_bits. */
    OE_CHECK(oe_safe_add_sizet(data_size, 5, &data_size));

    data = (uint8_t*)malloc(data_size);
    if (data == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    data_cur = data;
    data_size_cur = data_size;

    /* Copy label if it exists. */
    if (label)
        OE_CHECK(oe_memcpy_s(data_cur, data_size_cur, label, label_size));
    data_cur += label_size;
    data_size_cur -= label_size;

    /* Copy 0x00 byte. */
    *data_cur++ = 0;
    data_size_cur--;

    /* Copy context if it exists. */
    if (context)
        OE_CHECK(oe_memcpy_s(data_cur, data_size_cur, context, context_size));
    data_cur += context_size;
    data_size_cur -= context_size;

    /* Copy output_key_size_in_bits. */
    key_bits = _to_big_endian((uint32_t)(8 * output_key_size));
    OE_CHECK(oe_memcpy_s(data_cur, data_size_cur, &key_bits, 4));

    *fixed_data = data;
    *fixed_data_size = data_size;
    data = NULL;
    result = OE_OK;

done:
    if (data != NULL)
        free(data);

    return result;
}

oe_result_t oe_kdf_derive_key(
    oe_kdf_mode_t mode,
    const uint8_t* key,
    size_t key_size,
    const uint8_t* fixed_data,
    uint8_t fixed_data_size,
    uint8_t* derived_key,
    size_t derived_key_size)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!key || !derived_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    switch (mode)
    {
        case OE_KDF_HMAC_SHA256_CTR:
            OE_CHECK(
                kdf_hmac_sha256_ctr(
                    key,
                    key_size,
                    fixed_data,
                    fixed_data_size,
                    derived_key,
                    derived_key_size));
            break;
        default:
            OE_RAISE(OE_INVALID_PARAMETER);
    }

    result = OE_OK;

done:
    return result;
}
