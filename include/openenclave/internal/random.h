// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_RANDOM_INTERNAL_H
#define _OE_RANDOM_INTERNAL_H

#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

/**
 * Generate a sequence of random bytes.
 *
 * This function generates a sequence of random bytes using an entropy pool
 * managed by the crypto library used in the OE runtime. This abstraction is
 * split between host and enclave implementations.
 *
 * @param data the buffer that will be filled with random bytes
 * @param size the size of the buffer
 *
 * @return OE_OK on success
 */
oe_result_t oe_random_internal(void* data, size_t size);

OE_EXTERNC_END

#endif /* _OE_RANDOM_INTERNAL_H */
