// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/types.h>
#include <openenclave/internal/cpuid.h>

/* The list of cpuid leaves that are emulated.
 * Currently 0, 1, 4, 7, 0x80000000 and 0x80000001 leaves are
 * emulated.
 */
const uint32_t supported_cpuid_leaves[OE_CPUID_LEAF_COUNT] =
    {0, 1, 4, 7, 0x80000000, 0x80000001};
