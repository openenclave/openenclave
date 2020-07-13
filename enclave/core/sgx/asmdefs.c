// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/types.h>
#include <openenclave/internal/constants_x64.h>

/*
 * Initialization state for XSAVE area in the enclave.
 */
/* clang-format off */
OE_ALIGNED(XSAVE_ALIGNMENT) const uint32_t
OE_XSAVE_INITIAL_STATE[MINIMAL_XSTATE_AREA_LENGTH/sizeof(uint32_t)] = {

    /* LEGACY_XSAVE_AREA */
    /* Set FPU Control Word to ABI init value of 0x037F,
     * clear Status, Tag, OpCode, FIP words */
    0x037F, 0, 0, 0,

    /* Clear FDP bits, set MXCSR to ABI init value of 0x1F80
     * and MXCSR_MASK to all bits (0XFFFF) */
    0, 0, 0x1F80, 0xFFFF,

    /* Clear ST/MM0-7 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

    /* Clear XMM0-15 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

    /* Reserved bits up to end of LEGACY_XSAVE_AREA */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,

    /* XSAVE Header */
    /* Clear XSTATE_BV, set XCOMP_BV[63] = 1 to support compaction mode;
     * SGX-capable systems should support it */
    0, 0, 0, 0x80000000,

    /* Reserved XSAVE header bits */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};
/* clang-format on */
