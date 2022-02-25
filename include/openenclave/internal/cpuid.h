// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_CPUID_H
#define _OE_CPUID_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

#define OE_CPUID_OPCODE 0xA20F
#define OE_CPUID_LEAF_COUNT 6 /* 0,1,4,7,0x80000000,0x80000001 */
#define OE_CPUID_MAX_BASIC 7
#define OE_CPUID_MAX_EXTENDED 0x80000001

#define OE_CPUID_RAX 0
#define OE_CPUID_RBX 1
#define OE_CPUID_RCX 2
#define OE_CPUID_RDX 3
#define OE_CPUID_REG_COUNT 4

#define OE_CPUID_AESNI_FEATURE 0x02000000u  /* Leaf 1, subleaf 0, ECX */
#define OE_CPUID_RDRAND_FEATURE 0x40000000u /* Leaf 1, subleaf 0, ECX */
#define OE_CPUID_RDSEED_FEATURE 0x00040000u /* Leaf 7, subleaf 0, EBX */

extern const uint32_t supported_cpuid_leaves[OE_CPUID_LEAF_COUNT];

/**
 * Get the leaf index for the emulated cpuid leaf
 */
OE_INLINE uint32_t oe_get_emulated_cpuid_leaf_index(uint32_t leaf)
{
    uint32_t i = 0;
    while (i < OE_CPUID_LEAF_COUNT && leaf != supported_cpuid_leaves[i])
        i++;
    return i < OE_CPUID_LEAF_COUNT ? i : OE_UINT32_MAX;
}

/**
 * Check if a cpuid leaf is emulated.
 * Currently 0, 1, 4, 7, 0x80000000 and 0x80000001 leaves are
 * emulated. Note: leaf 1 is used by mbedtls to determine aesni support. The
 * higher 8 bits of ebx for leaf 1 is the current processor id (initial APIC
 * id). Since CPUID emulation returns cached values, this higher 8 bits of ebx
 * should not be relied upon for leaf 1.
 */
OE_INLINE bool oe_is_emulated_cpuid_leaf(uint32_t leaf)
{
    return (oe_get_emulated_cpuid_leaf_index(leaf) != OE_UINT32_MAX) ? true
                                                                     : false;
}

#endif /* _OE_CPUID_H */
