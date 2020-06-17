// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _ASM_COMMON_INC
#define _ASM_COMMON_INC

//==============================================================================
//
// This macro is used to cleanup the enclave Registers. Following registers will be scrubbed:
// 1. General Purpose registers excluding RAX, RBX, RCX, RDI, RSI, RBP, and RSP
//     RAX and RBX are input registers of EEXIT.
//     RCX is output register of EEXIT.
//     RDI and RSI is output parameters defined by SDK.
//     RBP and RSP will be set to host rbp and rsp right before EEXIT is executed.
//
// 2. Legacy SSE.
// 3. Extended XState components.
//==============================================================================
.macro oe_cleanup_registers
    // Scrub both Legacy SSE and extended XSTATEs.
    // Save the rax, rcx, rdi and rsi.
    mov %rax, %r12
    mov %rcx, %r13
    mov %rdi, %r14
    mov %rsi, %r15

    call oe_cleanup_xstates

    // Restore the rax, rcx, rdi and rsi.
    mov %r12, %rax
    mov %r13, %rcx
    mov %r14, %rdi
    mov %r15, %rsi

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
