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
//    - Initializes MXCSR to ABI-specified value 0x1FBF and MXCSR_MASK to 0xFFFF
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
    mov %rax, %r8
    mov %rdx, %r9

    // Check if extended states are supported by the OS.
    // If not, fallback to FXRSTOR to clear legacy SSE states only.
    // Otherwise, clear both legacy SSE states and extended states with XRSTOR.
    movl    oe_is_xsave_supported(%rip), %eax
    cmpl    $0, %eax
    jz      1f

    // Set the XSAVE_MASK
    mov $0xFFFFFFFF, %eax
    mov $0xFFFFFFFF, %edx

    // Restore initial enclave XSAVE state
    xrstor64 OE_XSAVE_INITIAL_STATE(%rip)
    jmp     2f
1:
    // Restore initial enclave legacy SSE state
    fxrstor64 OE_XSAVE_INITIAL_STATE(%rip)
2:
    // Put a lfence after changing MXCSR for MXCSR Configuration Dependent
    // Timing (MCDT) mitigation
    lfence
    // Restore the registers
    mov %r8, %rax
    mov %r9, %rdx
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
    xor %r9,  %r9
    xor %r10, %r10
    xor %r12, %r12
    xor %r13, %r13
    xor %r14, %r14
    xor %r15, %r15

    // Zero out the status flags (CF, PF, AF, SF, OF) that could leak
    // information about instructions executed by the enclave without using stack.
    // Doing so avoiding using untrusted host stack when cleaning up registers
    // during enclave enter and exit routines.
    // To clear system and control flags, see oe_cleanup_flags_on_enclave_stack
    // for more detail.
    mov %rax, %r8
    xor %rax, %rax
    test %al, %al // Clear OF
    sahf // Clear SF, ZF AF, PF, and CF
    mov %r8, %rax

    // No need to clear r8, which equals to rax (return value to the host)

.endm

//==============================================================================
//
// This macro is used to clean up the enclave FLAGS register, including not only
// status but also system and control flags.
//
// The macro does not reserve r15 and require consuming stack. Please make sure
// using the macro within the enclave stack. Currently, the macro is only used
// during oe_enter.
//
//==============================================================================
.macro oe_cleanup_flags_on_enclave_stack
    xor %r15, %r15
    pushq %r15
    popfq
.endm

#endif
