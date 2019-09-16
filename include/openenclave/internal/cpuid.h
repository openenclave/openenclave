// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CPUID_H
#define _OE_CPUID_H

#include <openenclave/bits/defs.h>

#define OE_CPUID_OPCODE 0xA20F
#define OE_CPUID_LEAF_COUNT 8
#define OE_CPUID_EXTENDED_CPUID_LEAF 0x80000000

#define OE_CPUID_RAX 0
#define OE_CPUID_RBX 1
#define OE_CPUID_RCX 2
#define OE_CPUID_RDX 3
#define OE_CPUID_REG_COUNT 4

#define OE_CPUID_AESNI_FEATURE 0x02000000u  /* Leaf 1, subleaf 0, ECX */
#define OE_CPUID_RDRAND_FEATURE 0x40000000u /* Leaf 1, subleaf 0, ECX */
#define OE_CPUID_RDSEED_FEATURE 0x00040000u /* Leaf 7, subleaf 0, EBX */

/**
 * The list of cpuid leafs that are emulated.
 * Currently 0, 1, 4, 7 leafs are emulated, consistent with Intel SDK.
 * Note: leaf 1 is used by mbedtls to determine aesni support.
 * The higher 8 bits of ebx for leaf 1 is the current processor id (initial APIC
 * id). Since CPUID emulation returns cached values, this higher 8 bits of ebx
 * should not be relied upon for leaf 1.
 */
OE_INLINE bool oe_is_emulated_cpuid_leaf(uint32_t leaf)
{
    return (leaf == 0) || (leaf == 1) || (leaf == 4) || (leaf == 7);
}

#endif /* _OE_CPUID_H */
