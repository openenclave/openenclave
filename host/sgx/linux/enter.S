// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../asmdefs.h"
#include <openenclave/internal/constants_x64.h>
#include <openenclave/internal/context.inc>

//==============================================================================
//
// void __morestack(
//     [IN] void* tcs,                  /* RDI */
//     [IN] uint64_t aep,               /* RSI */
//     [IN] uint64_t arg1,              /* RDX */
//     [IN] uint64_t arg2,              /* RCX */
//     [OUT] uint64_t* arg3,            /* R8 */
//     [OUT] uint64_t* arg4,            /* R9 */
//     [IN] oe_enclave_t* enclave);       /* on stack */
//
// Registers:
//     RDI   - tcs: thread control structure
//     RSI   - aep: asynchronous execution procedure
//     RDX   - arg1
//     RCX   - arg2
//     R8    - arg3
//     R9    - arg4
//
// N.B: Don't change the function name, otherwise debugger can't work.
// GDB depends on this hardcode function name when does stack walking for split
// stack.
//
// Note that oe_enter is defined to __morestack
//
//==============================================================================

#define ENCLAVE         (+2*OE_WORDSIZE)(%rbp)
#define TCS             (-1*OE_WORDSIZE)(%rbp)
#define AEP             (-2*OE_WORDSIZE)(%rbp)
#define ARG1            (-3*OE_WORDSIZE)(%rbp)
#define ARG2            (-4*OE_WORDSIZE)(%rbp)
#define ARG3            (-5*OE_WORDSIZE)(%rbp)
#define ARG4            (-6*OE_WORDSIZE)(%rbp)
#define FX_SPACE        (-72*OE_WORDSIZE)(%rbp)	// 512 bytes needed for fx
#define PARAMS_SPACE    (+72*OE_WORDSIZE)

.globl __morestack
.type __morestack, @function
__morestack:
    // Setup stack frame.
    push %rbp
    mov %rsp, %rbp // Stack is 16-byte aligned here.

    // Save parameters on stack for later reference:
    sub $PARAMS_SPACE, %rsp
    mov %rdi, TCS
    mov %rsi, AEP
    mov %rdx, ARG1
    mov %rcx, ARG2
    mov %r8,  ARG3
    mov %r9,  ARG4

    // Save System V x64 callee saved registers
    push %r15
    push %r14
    push %r13
    push %r12
    push %rbx

.execute_eenter:
    // Save flags and floating-point state.
    fxsave FX_SPACE
    pushfq

    // The EENTER(RBX=TCS, RCX=AEP, RDI=ARG1, RSI=ARG2) contract:
    // Input:
    //      RBX=TCS, RCX=AEP, RDI=ARG1, RSI=ARG2,
    //      RBP=Current host stack rbp,
    //      RSP=Current host stack sp.
    //      All other registers are NOT used/ignored.
    // Output:
    //      RDI=ARG1OUT, RSI=ARG2OUT,
    //      RBP and RSP are not changed,
    //      All other Registers are clobbered.
    mov TCS, %rbx
    mov AEP, %rcx
    mov ARG1, %rdi
    mov ARG2, %rsi

    mov ENCLAVE, %r10
    cmpb $0, OE_ENCLAVE_OFFSET_SIMULATE(%r10)
    je .execute_enclu

.execute_enclu_sim:
    // For simulation mode, make the following changes
    mov $0, %rax  // CSSA = 0
    lea .return_address(%rip), %rcx
    mov 72(%rbx), %rdx
    jmp *%rdx

.execute_enclu:
    mov $ENCLU_EENTER, %rax
    ENCLU

.return_address:
    // Save return values.
    mov %rdi, ARG1
    mov %rsi, ARG2

    // Restore flags and floating-point state.
    popfq
    fxrstor FX_SPACE

    // Check if an OCALL needs to be dispatched.
    mov %rdi, %r10
    shr $48, %r10
    cmpq $OE_OCALL_CODE, %r10
    jne .return_from_ecall

.dispatch_ocall:
    // ARG1 is already in RDI
    // ARG2 is already in RSI
    mov TCS, %rdx
    mov AEP, %rcx
    lea ARG1, %r8
    lea ARG2, %r9
    push ENCLAVE  // Stack is 16-byte aligned after this.
    call __oe_host_stack_bridge@PLT
    add $8, %rsp

    jmp .execute_eenter

.return_from_ecall:
    // Write results.
    // RSI contains arg1, RDI contains arg2.
    mov ARG3, %rbx
    mov %rdi, (%rbx)
    mov ARG4, %rcx
    mov %rsi, (%rcx)

    // Restore callee saved registers.
    pop %rbx
    pop %r12
    pop %r13
    pop %r14
    pop %r15

    // Restore stack frame.
    mov %rbp, %rsp
    pop %rbp

    ret
.size __morestack, .-__morestack
