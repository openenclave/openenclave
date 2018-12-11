// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../asmdefs.h"
#include <openenclave/internal/constants_x64.h>

//==============================================================================
//
// void oe_enter_sim(
//     [IN] void* tcs,
//     [IN] void (*aep)(),
//     [IN] uint64_t arg1,
//     [IN] uint64_t arg2,
//     [OUT] uint64_t* arg3,
//     [OUT] uint64_t* arg4,
//     [IN] oe_enclave_t* enclave);
//
// Registers:
//     RDI   - tcs: thread control structure (extended)
//     RSI   - aep: asynchronous execution procedure
//     RDX   - arg1
//     RCX   - arg2
//     R8    - arg3
//     R9    - arg4
//
//==============================================================================

#define TCS             (-1*OE_WORDSIZE)(%rbp)
#define AEP             (-2*OE_WORDSIZE)(%rbp)
#define ARG1            (-3*OE_WORDSIZE)(%rbp)
#define ARG2            (-4*OE_WORDSIZE)(%rbp)
#define ARG3            (-5*OE_WORDSIZE)(%rbp)
#define ARG4            (-6*OE_WORDSIZE)(%rbp)
#define ENCLAVE          (-7*OE_WORDSIZE)(%rbp)
#define ARG1OUT         (-8*OE_WORDSIZE)(%rbp)
#define ARG2OUT         (-9*OE_WORDSIZE)(%rbp)
#define CSSA            (-10*OE_WORDSIZE)(%rbp)
#define RSP             (-11*OE_WORDSIZE)(%rbp)
#define HOST_CONTEXT    (-12*OE_WORDSIZE)(%rbp)
#define PARAMS_SPACE    ((12*OE_WORDSIZE) + OE_CONTEXT_SIZE)

.globl oe_enter_sim
.type oe_enter_sim, @function
oe_enter_sim:
.cfi_startproc

    // Setup stack frame:
    push %rbp
    mov %rsp, %rbp

    // Save parameters on stack for later reference:
    sub $PARAMS_SPACE, %rsp
    mov %rdi, TCS
    mov %rsi, AEP
    mov %rdx, ARG1
    mov %rcx, ARG2
    mov %r8, ARG3
    mov %r9, ARG4
    mov 16(%rbp), %rax  // enclave parameter
    mov %rax, ENCLAVE
    movq $0, CSSA

    // The host context will be saved in the host stack.
    mov %rsp, HOST_CONTEXT

    // Save registers:
    push %rbx

.call_start:

    // Save the current context.
    mov HOST_CONTEXT, %rdi
    call oe_snap_current_context@PLT

    // Save the stack pointer so enclave can use the stack.
    mov %rsp, RSP

    // Call start(RAX=CSSA, RBX=TCS, RCX=RETADDR, RDI=ARG1, RSI=ARG2)
    mov CSSA, %rax
    mov TCS, %rbx
    mov 72(%rbx), %rdx  // RDX=TCS.u.main (72)
    mov ARG1, %rdi
    mov ARG2, %rsi
    lea .retaddr(%rip), %rcx
    jmp *%rdx
.retaddr:
    mov %rdi, ARG1OUT
    mov %rsi, ARG2OUT

    // Align the stack since enclave code change the host rsp for call out.
    and $-16, %rsp

    // Restore the saved host context.
    mov HOST_CONTEXT, %rdi
    call oe_restore_partial_context@PLT

.dispatch_ocall_sim:

    // Save registers that could get clobbered below or by function call.
    push %rdi
    push %rsi
    push %rdx
    push %rcx
    push %rbx
    push %r8
    push %r9
    push %r12
    push %r13
    // Push one extra register to keep the stack aligned.
    push %r13

    // RAX = __oe_dispatch_ocall(
    //     RDI=arg1
    //     RSI=arg2
    //     RDX=arg1_out
    //     RCX=arg2_out
    //     R8=TCS)
    mov ARG1OUT, %rdi
    mov ARG2OUT, %rsi
    leaq ARG1OUT, %rdx
    leaq ARG2OUT, %rcx
    mov TCS, %r8
    mov ENCLAVE, %r9
    call __oe_dispatch_ocall@PLT

    // Restore registers saved above:
    pop %r13
    pop %r13
    pop %r12
    pop %r9
    pop %r8
    pop %rbx
    pop %rcx
    pop %rdx
    pop %rsi
    pop %rdi

    // Restore the stack pointer:
    mov RSP, %rsp

    // If this was not an OCALL, then return from ECALL.
    // ecall-return-check.
    cmp $0, %rax
    jne .return_from_ecall_sim

    // Stop speculative execution at fallthrough of conditional
    // ecall-return-check.
    lfence

    // (RDI=TCS, RDX=ARG1, RCX=ARG2)
    mov ARG1OUT, %rax
    mov %rax, ARG1
    mov ARG2OUT, %rax
    mov %rax, ARG2
    jmp .call_start

.return_from_ecall_sim:
    // Stop speculative execution at target of conditional jump
    // ecall-return-check.
    lfence
    
    // Set output parameters:
    mov ARG1OUT, %rax
    mov %rax, (%r8) /* arg3 */
    mov ARG2OUT, %rax
    mov %rax, (%r9) /* arg4 */

    // Restore registers:
    pop %rbx

    // Return parameters space:
    add $PARAMS_SPACE, %rsp

    // Restore stack frame:
    pop %rbp

    ret

.forever:
    jmp .forever

.cfi_endproc
