// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENTROPY_H
#define _OE_ENTROPY_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * Generates a sequence of high quality sequence of random bytes that
 * is suitable for a seed to a pseudorandom number generator (PRNG).
 *
 * This function will block if there is insufficient hardware entropy.
 *
 * @param data the buffer that will be filled with random bytes
 * @param size the size of the buffer
 *
 * @return OE_OK on success
 */
oe_result_t oe_get_entropy(void* data, size_t size);

OE_EXTERNC_END

#endif /* _OE_ENTROPY_H */
