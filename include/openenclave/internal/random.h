// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_RANDOM_H
#define _OE_RANDOM_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

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

/**
 * Generate a sequence of random bytes using Intel RDRAND instruction
 *
 * This function generates 8 random bytes using direct call to Intel's RDRAND
 * instruction. This method will block if there is insufficient hardware
 * entropy to provide the full 64-bits of randomness.
 *
 * @return OE_OK on success
 */
uint64_t oe_rdrand(void);

OE_EXTERNC_END

#endif /* _OE_RANDOM_H */
