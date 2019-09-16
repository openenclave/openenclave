// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENTROPY_H
#define _OE_ENTROPY_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * The kind of entropy returned by the oe_get_entropy method, as classified
 * by the Digital Random Number Generator (DRNG) implementation used.
 */
typedef enum _oe_entropy_kind
{
    OE_ENTROPY_KIND_NONE = 0,
    OE_ENTROPY_KIND_RDRAND = 1,
    OE_ENTROPY_KIND_RDSEED = 2,
    OE_ENTROPY_KIND_OPTEE = 3,
    __OE_ENTROPY_KIND_MAX = OE_ENUM_MAX
} oe_entropy_kind_t;

/**
 * Generates a sequence of high quality sequence of random bytes that
 * is suitable for a seed to a pseudorandom number generator (PRNG).
 *
 * This function will block if there is insufficient hardware entropy.
 *
 * @param data The buffer that will be filled with random bytes
 * @param size The size of the buffer
 * @param kind The kind of entropy returned as classified by the Digital
 *             Random Number Generator (DRNG) implementation used.
 *
 * @return OE_OK on success
 */
oe_result_t oe_get_entropy(void* data, size_t size, oe_entropy_kind_t* kind);

OE_EXTERNC_END

#endif /* _OE_ENTROPY_H */
