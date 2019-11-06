// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../asmdefs.h"
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

#define TCS             (-1*OE_WORDSIZE)(%rbp)
#define AEP             (-2*OE_WORDSIZE)(%rbp)
#define ARG1            (-3*OE_WORDSIZE)(%rbp)
#define ARG2            (-4*OE_WORDSIZE)(%rbp)
#define ARG3            (-5*OE_WORDSIZE)(%rbp)
#define ARG4            (-6*OE_WORDSIZE)(%rbp)
#define ENCLAVE         (-7*OE_WORDSIZE)(%rbp)
#define ARG1OUT         (-8*OE_WORDSIZE)(%rbp)
#define ARG2OUT         (-9*OE_WORDSIZE)(%rbp)
#define RSP             (-10*OE_WORDSIZE)(%rbp)
#define HOST_CONTEXT    (-11*OE_WORDSIZE)(%rbp)
// We need an extra OE_WORDSIZE to keep the stack aligned.
#define PARAMS_SPACE    ((12*OE_WORDSIZE) + OE_CONTEXT_SIZE)

.globl __morestack
.type __morestack, @function
__morestack:

    // Setup stack frame:
    push %rbp
    mov %rsp, %rbp

    // Save parameters on stack for later reference:
    sub $PARAMS_SPACE, %rsp
    mov %rdi, TCS
    mov %rsi, AEP
    mov %rdx, ARG1
    mov %rcx, ARG2
    mov %r8,  ARG3
    mov %r9,  ARG4
    mov 16(%rbp), %rax  // enclave parameter
    mov %rax, ENCLAVE

    // The host context will be saved in the host stack.
    mov %rsp, HOST_CONTEXT

.execute_eenter:

    // Save the current context.
    mov HOST_CONTEXT, %rdi
    call oe_snap_current_context@PLT

    // Save the stack pointer so enclave can use the stack.
    mov %rsp, RSP

    // The EENTER(RBX=TCS, RCX=AEP, RDI=ARG1, RSI=ARG2) contract:
    // Input:
    //      RBX=TCS, RCX=AEP, RDI=ARG1, RSI=ARG2,
    //      RBP=Current host stack rbp,
    //      RSP=Current host stack sp.
    //      All other registers are NOT used/ignored.
    // Output:
    //      RDI=ARG1OUT, RSI=ARG2OUT,
    //      RBP is not changed,
    //      RSP might be decreased because of host stack memory allocation.
    //      All other Registers are clobbered.
    mov TCS, %rbx
    mov AEP, %rcx
    mov ARG1, %rdi
    mov ARG2, %rsi
    mov $ENCLU_EENTER, %rax
    ENCLU

    // Align the stack since enclave code change the host rsp for call out.
    and $-16, %rsp

    mov %rdi, ARG1OUT
    mov %rsi, ARG2OUT

    // Restore the saved host context.
    mov HOST_CONTEXT, %rdi
    call oe_restore_partial_context@PLT

    // Check if it is an OCALL needed to be dispatched.
    // ecall-return-check.
    mov ARG1OUT, %r10
    shr $48, %r10
    cmpq $OE_OCALL_CODE, %r10
    jne .return_from_ecall

.dispatch_ocall:
    // Stop speculative execution at fallthrough of conditional
    // ecall-return-check.
    lfence

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

    // RAX = __oe_host_stack_bridge(
    //     RDI=arg1
    //     RSI=arg2
    //     RDX=arg1_out
    //     RCX=arg2_out
    //     R8=TCS,
    //     R9=RSP)
    mov ARG1OUT, %rdi
    mov ARG2OUT, %rsi
    leaq ARG1OUT, %rdx
    leaq ARG2OUT, %rcx
    mov TCS, %r8
    mov RSP, %r9
    push ENCLAVE // push enclave parameter
    call __oe_host_stack_bridge@PLT
    add $8, %rsp // pop enclave parameter

    // Restore registers (except RDI and RSI)
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
    // ecall-return-check-1.
    cmp $0, %rax
    jne .return_from_ecall

    // Stop speculative execution at fallthrough of conditional
    // ecall-return-check-1.
    lfence
    
    // Execute EENTER(RBX=TCS, RCX=AEP, RDI=ARG1, RSI=ARG2)
    mov ARG1OUT, %rax
    mov %rax, ARG1
    mov ARG2OUT, %rax
    mov %rax, ARG2
    jmp .execute_eenter

.return_from_ecall:
    // Stop speculative execution at target of conditional jump
    // ecall-return-check and ecall-return-check-1.
    lfence

    // Set output parameters:
    mov ARG1OUT, %rax
    mov %rax, (%r8) /* arg3 */
    mov ARG2OUT, %rax
    mov %rax, (%r9) /* arg3 */

    // Restore stack frame:
    mov %rbp, %rsp
    pop %rbp

    ret

.size __morestack, .-__morestack

//==============================================================================
//
// __oe_host_stack_bridge(
//     [IN] uint64_t arg1,      /* RDI */
//     [IN] uint64_t arg2,      /* RSI */
//     [OUT] uint64_t* arg3,    /* RDX */
//     [OUT] uint64_t* arg4,    /* RCX */
//     [IN] void* tcs,          /* R8 */
//     [IN] void* rsp,          /* R9 */
//     [IN] uint64_t enclave)    /* STACK */
//
// This function is wrapper of __oe_dispatch_ocall. It is needed to stitch
// the host stack and enclave stack together.
//
//==============================================================================

#define HB_SAVED_OCALL_RETURN   (0*OE_WORDSIZE)(%rsp)
#define HB_SAVED_ARG1           (1*OE_WORDSIZE)(%rsp)
#define HB_SAVED_ARG2           (2*OE_WORDSIZE)(%rsp)
#define HB_SAVED_ARG3           (3*OE_WORDSIZE)(%rsp)
#define HB_SAVED_ARG4           (4*OE_WORDSIZE)(%rsp)
#define HB_SAVED_TCS            (5*OE_WORDSIZE)(%rsp)
#define HB_SAVED_RSP            (6*OE_WORDSIZE)(%rsp)
#define HB_SAVED_ENCLAVE         (7*OE_WORDSIZE)(%rsp)
#define HB_SAVED_RETURN_ADDR    (8*OE_WORDSIZE)(%rsp)
#define HB_SAVED_FRAME_POINTER  (9*OE_WORDSIZE)(%rsp)
#define HB_STACK_LENGTH         (10*OE_WORDSIZE)

.globl __oe_host_stack_bridge
.type __oe_host_stack_bridge, @function
.type oe_notify_ocall_start,@function
.hidden oe_notify_ocall_start
.type oe_notify_ocall_end,@function
.hidden oe_notify_ocall_end
__oe_host_stack_bridge:
.cfi_startproc
    push %rbp
.cfi_def_cfa_offset 16
.cfi_offset rbp,-16
    mov %rsp, %rbp
.cfi_def_cfa_register   rbp
    sub $HB_STACK_LENGTH, %rsp

    // Save the current return address and frame point of __oe_host_stack_bridge
    // into stack.
    mov 0(%rbp), %rax
    mov %rax, HB_SAVED_FRAME_POINTER
    mov (1*OE_WORDSIZE)(%rbp), %rax
    mov %rax, HB_SAVED_RETURN_ADDR

    // Save the function parameters needed for __oe_dispatch_ocall into stack.
    mov %rdi, HB_SAVED_ARG1     // arg1
    mov %rsi, HB_SAVED_ARG2     // arg2
    mov %rdx, HB_SAVED_ARG3     // arg3
    mov %rcx, HB_SAVED_ARG4     // arg4
    mov %r8,  HB_SAVED_TCS      // tcs
    mov %r9, HB_SAVED_RSP       // rsp
    mov 16(%rbp), %rax          // enclave
    mov %rax, HB_SAVED_ENCLAVE

    // Notify that an ocall happens in current host thread.
    // oe_notify_ocall_start(rdi=host_frame_pointer, rsi=tcs)
    mov %rbp, %rdi
    mov %r8,  %rsi
    call oe_notify_ocall_start@PLT

    // Restore the parameters for __oe_dispatch_ocall.
    mov HB_SAVED_ARG1, %rdi
    mov HB_SAVED_ARG2, %rsi
    mov HB_SAVED_ARG3, %rdx
    mov HB_SAVED_ARG4, %rcx
    mov HB_SAVED_TCS, %r8
    mov HB_SAVED_ENCLAVE, %r9

    // Do actual OCALL.
    call __oe_dispatch_ocall@PLT

    // Save the return value of OCALL dispatch.
    mov %rax, HB_SAVED_OCALL_RETURN

    // Notify that an ocall is done in current host thread.
    // oe_notify_ocall_start(rdi=host_frame_pointer, rsi=tcs)
    mov %rbp, %rdi
    mov HB_SAVED_TCS, %rsi
    call oe_notify_ocall_end@PLT

    // Because of stack stitching, the return address might be overwritten by
    // gdb. Restore the current return address and frame point of
    // __oe_host_stack_bridge from stack.
    mov HB_SAVED_FRAME_POINTER, %rax
    mov %rax, (0*OE_WORDSIZE)(%rbp)
    mov HB_SAVED_RETURN_ADDR, %rax
    mov %rax, (1*OE_WORDSIZE)(%rbp)

    // Restore the return value of OCALL dispatch.
    mov HB_SAVED_OCALL_RETURN, %rax

    leave
    ret

.cfi_endproc
