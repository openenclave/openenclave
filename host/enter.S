#include "asmdefs.h"

//==============================================================================
//
// void __morestack(
//     [IN] void* tcs,
//     [IN] void (*aep)(),
//     [IN] uint64_t arg1,
//     [IN] uint64_t arg2,
//     [OUT] uint64_t* arg3,
//     [OUT] uint64_t* arg4);
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
//==============================================================================

#define PARAMS_SPACE 128
#define TCS     -8(%rbp)
#define AEP     -16(%rbp)
#define ARG1    -24(%rbp)
#define ARG2    -32(%rbp)
#define ARG3    -40(%rbp)
#define ARG4    -48(%rbp)
#define ARG1OUT -56(%rbp)
#define ARG2OUT -64(%rbp)
#define RSP     -72(%rbp)

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

    // Save registers:
    push %rbx

.execute_eenter:

    // Save the stack pointer so enclave can use the stack.
    mov %rsp, RSP

    // EENTER(RBX=TCS, RCX=AEP, RDI=ARG1, RSI=ARG2)
    mov TCS, %rbx
    mov AEP, %rcx
    mov ARG1, %rdi
    mov ARG2, %rsi
    mov $ENCLU_EENTER, %rax
    ENCLU

    mov %rdi, ARG1OUT
    mov %rsi, ARG2OUT

    // Check if it is an OCALL needed to be dispatched.
    mov %rdi, %r10
    shr $48, %r10
    cmpq $OE_OCALL_CODE, %r10
    jne .return_from_ecall

.dispatch_ocall:

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

    // Call _OE_HostStackBridge():
    //     RDI=arg1
    //     RSI=arg2
    //     RDX=arg1Out
    //     RCX=arg2Out
    //     R8=TCS)
    mov ARG1OUT, %rdi
    mov ARG2OUT, %rsi
    leaq ARG1OUT, %rdx
    leaq ARG2OUT, %rcx
    mov TCS, %r8
    mov RSP, %r9
    call _OE_HostStackBridge

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
    cmp $0, %rax
    jne .return_from_ecall

    // Execute EENTER(RBX=TCS, RCX=AEP, RDI=ARG1, RSI=ARG2)
    mov ARG1OUT, %rax
    mov %rax, ARG1
    mov ARG2OUT, %rax
    mov %rax, ARG2
    jmp .execute_eenter

.return_from_ecall:

    // Set output parameters:
    mov ARG1OUT, %rax
    mov %rax, (%r8) /* arg3 */
    mov ARG2OUT, %rax
    mov %rax, (%r9) /* arg3 */

    // Restore registers:
    pop %rbx

    // Return parameters space:
    add $PARAMS_SPACE, %rsp

    // Restore stack frame:
    pop %rbp

    ret

.size __morestack, .-__morestack

//==============================================================================
// 
// _OE_HostStackBridge():
//
//     This function is wrapper of __OE_DispatchOCall. It is needed to stitch 
//     the host stack and enclave stack together.
//
//==============================================================================

#define HB_STACK_LENGTH         0X50
#define HB_SAVED_ARG1           (0*OE_WORDSIZE)(%rsp)
#define HB_SAVED_OCALL_RETURN   (0*OE_WORDSIZE)(%rsp)
#define HB_SAVED_ARG2           (1*OE_WORDSIZE)(%rsp)
#define HB_SAVED_ARG3           (2*OE_WORDSIZE)(%rsp)
#define HB_SAVED_ARG4           (3*OE_WORDSIZE)(%rsp)
#define HB_SAVED_ARG5           (4*OE_WORDSIZE)(%rsp)
#define HB_SAVED_ARG6           (5*OE_WORDSIZE)(%rsp)
#define HB_SAVED_RETURN_ADDR    (6*OE_WORDSIZE)(%rsp)
#define HB_SAVED_FRAME_POINTER  (7*OE_WORDSIZE)(%rsp)

.globl _OE_HostStackBridge
.type _OE_HostStackBridge, @function
.type _OE_NotifyOCallStart,@function
.hidden _OE_NotifyOCallStart
.type _OE_NotifyOCallEnd,@function
.hidden _OE_NotifyOCallEnd
_OE_HostStackBridge:
.cfi_startproc
    push %rbp
.cfi_def_cfa_offset 16
.cfi_offset rbp,-16
    mov %rsp, %rbp
.cfi_def_cfa_register   rbp
    sub $HB_STACK_LENGTH, %rsp

    // Save the current return address and frame point of _OE_HostStackBridge 
    // into stack.
    mov 0(%rbp), %rax
    mov %rax, HB_SAVED_FRAME_POINTER
    mov (1*OE_WORDSIZE)(%rbp), %rax
    mov %rax, HB_SAVED_RETURN_ADDR

    // Save the function parameters needed for __OE_DispatchOCall into stack.
    mov %rdi, HB_SAVED_ARG1
    mov %rsi, HB_SAVED_ARG2
    mov %rdx, HB_SAVED_ARG3
    mov %rcx, HB_SAVED_ARG4
    mov %r8,  HB_SAVED_ARG5
    mov %r9, HB_SAVED_ARG6

    // Notify that an ocall happens in current host thread.
    // _OE_NotifyOCallStart(rdi=host_frame_pointer, rsi=tcs)
    mov %rbp, %rdi
    mov %r8,  %rsi
    call _OE_NotifyOCallStart

    // Restore the parameters for __OE_DispatchOCall.
    mov HB_SAVED_ARG1, %rdi
    mov HB_SAVED_ARG2, %rsi
    mov HB_SAVED_ARG3, %rdx
    mov HB_SAVED_ARG4, %rcx
    mov HB_SAVED_ARG5, %r8
    mov HB_SAVED_ARG6, %r9

    // Do actual OCALL.
    call __OE_DispatchOCall
    
    // Save the return value of OCALL dispatch.
    mov %rax, HB_SAVED_OCALL_RETURN

    // Notify that an ocall is done in current host thread.
    // _OE_NotifyOCallStart(rdi=host_frame_pointer, rsi=tcs)
    mov %rbp, %rdi
    mov HB_SAVED_ARG5, %rsi
    call _OE_NotifyOCallEnd

    // Because of stack stitching, the return address might be overwritten by 
    // gdb. Restore the current return address and frame point of 
    // _OE_HostStackBridge from stack.
    mov HB_SAVED_FRAME_POINTER, %rax
    mov %rax, (0*OE_WORDSIZE)(%rbp)
    mov HB_SAVED_RETURN_ADDR, %rax
    mov %rax, (1*OE_WORDSIZE)(%rbp)
    
    // Restore the return value of OCALL dispatch.
    mov HB_SAVED_OCALL_RETURN, %rax

    leave
    ret

.cfi_endproc
