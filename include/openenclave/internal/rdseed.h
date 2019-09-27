// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_RDSEED_H
#define _OE_RDSEED_H

#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * Generate a sequence of random bytes using Intel RDSEED instruction
 *
 * This function generates 8 random bytes using direct call to Intel's RDSEED
 * instruction. This method will block if there is insufficient hardware
 * entropy to provide the full 64-bits of randomness.
 *
 * @return uint64_t 8-bytes of randomness.
 */
uint64_t oe_rdseed(void);

OE_EXTERNC_END

#endif /* _OE_RDSEED_H */
