// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _ASM_COMMON_INC
#define _ASM_COMMON_INC

//==============================================================================
//
// This macro is used to reset all XSAVE supported state components to a
// clean initial state. This includes:
//
//  - The legacy SSE state:
//    - Initializes the FPU control word to ABI-specified value 0x037F
//    - Initializes MXCSR to ABI-specified value 0x1F80 and MXCSR_MASK to 0xFFFF
//    - Clears FPU Status, Tag, OpCode, and FIP words
//    - Clears all FDP bits
//    - Clears all MMX/FPU registers
//    - Clears all XMM registers
//
//  - The extended XSAVE state components:
//    - Clears all XSTATE_BV bits
//    - Sets XCOMP_BV bit-63 to support compaction mode
//    - Clears all other XCOMP_BV bits
//
//==============================================================================
.macro oe_cleanup_xstates
    // Preserve registers being used
    push %rax
    push %rdx

    // Set the XSAVE_MASK
    mov $0xFFFFFFFF, %eax
    mov $0xFFFFFFFF, %edx

    // Restore initial enclave XSAVE state
    xrstor64 OE_XSAVE_INITIAL_STATE(%rip)

    // Restore the registers
    pop %rdx
    pop %rax
.endm

//==============================================================================
//
// This macro is used to clean up the enclave registers in addition to the
// extended states (see oe_cleanup_xstates).
//
// It scrubs all general purpose registers excluding:
//  - RAX and RBX, which are used as input registers of EEXIT.
//  - RCX, which is used as the output register of EEXIT.
//  - RDI and RSI, which are used as output parameters defined by SDK.
//  - RBP and RSP, which will be set to host values of RBP & RSP right before
//      EEXIT is executed.
//
//==============================================================================
.macro oe_cleanup_registers
    // Scrub both Legacy SSE and extended XSTATEs.
    oe_cleanup_xstates

    // Zero out GPRs.
    // Retain r11 since it is used as a reference to the td structure.
    // The exit and enter routines are responsible for clearing r11
    // prior to returning.
    xor %rdx, %rdx
    xor %r8,  %r8
    xor %r9,  %r9
    xor %r10, %r10
    xor %r12, %r12
    xor %r13, %r13
    xor %r14, %r14
    xor %r15, %r15

    // zero out flags
    push %r15
    popfq
.endm

#endif
