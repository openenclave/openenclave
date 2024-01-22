// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/types.h>
#include <openenclave/internal/constants_x64.h>

/*
 * Initialization state for XSAVE area in the enclave.
 */
/* clang-format off */
OE_ALIGNED(OE_XSAVE_ALIGNMENT) const uint32_t
OE_XSAVE_INITIAL_STATE[OE_MINIMAL_XSTATE_AREA_SIZE/sizeof(uint32_t)] = {

    /* FXSAVE (a.k.a. legacy XSAVE) area */
    /* Set FPU Control Word to ABI init value of 0x037F,
     * clear Status, Tag, OpCode, FIP words */
    0x037F, 0, 0, 0,

    /* Clear FDP bits, set MXCSR to ABI init value of 0x1FBF
     * and MXCSR_MASK to all bits (0XFFFF) */
    0, 0, 0x1FBF, 0xFFFF,

    /* Clear ST/MM0-7 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

    /* Clear XMM0-15 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

    /* Reserved bits up to end of FXSAVE area */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,

    /* XSAVE Header */
    /* Set XSTATE_BV[1] to 1 (SSE state) */
    2, 0,
    /* Set XCOMP_BV[1] to 1 (SSE state), allowing non-default
     * MXCSR value to be restored.
     * Also, set XCOMP_BV[63] to 1 for compaction mode */
    2, 0x80000000,

    /* Reserved XSAVE header bits */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};
/* clang-format on */
