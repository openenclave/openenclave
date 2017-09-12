#include "asmdefs.h"

//==============================================================================
//
// void OE_EnterSim(
//     [IN] void* tcs,
//     [IN] void (*aep)(),
//     [IN] uint64_t arg1,
//     [IN] uint64_t arg2,
//     [OUT] uint64_t* arg3,
//     [OUT] uint64_t* arg4);
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

#define PARAMS_SPACE 128
#define TCS     -8(%rbp)
#define AEP     -16(%rbp)
#define ARG1    -24(%rbp)
#define ARG2    -32(%rbp)
#define ARG3    -40(%rbp)
#define ARG4    -48(%rbp)
#define ARG1OUT -56(%rbp)
#define ARG2OUT -64(%rbp)
#define CSSA    -72(%rbp)

.globl OE_EnterSim
.type OE_EnterSim, @function
OE_EnterSim:
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
    movq $0, CSSA

    // Save registers:
    push %rbx

.call_oe_main:

    // Call OE_Main(RAX=CSSA, RBX=TCS, RCX=RETADDR, RDI=ARG1, RSI=ARG2)
    mov CSSA, %rax
    mov TCS, %rbx
    mov 72(%rbx), %rdx  // RDX=TCS.u.main (72)
    mov ARG1, %rdi
    mov ARG2, %rsi
    lea .retaddr, %rcx
    jmp *%rdx

    mov %rdi, ARG1OUT
    mov %rsi, ARG2OUT

.retaddr:

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

    // Call __OE_DispatchOCall():
    //     RDI=arg1
    //     RSI=arg2
    //     RDX=arg1Out
    //     RCX=arg2Out
    //     R8=TCS
    mov ARG1OUT, %rdi
    mov ARG2OUT, %rsi
    leaq ARG1OUT, %rdx
    leaq ARG2OUT, %rcx
    mov TCS, %r8
    call __OE_DispatchOCall

    // Restore registers saved above:
    pop %r13
    pop %r12
    pop %r9
    pop %r8
    pop %rbx
    pop %rcx
    pop %rdx
    pop %rsi
    pop %rdi

    // If this was not an OCALL, then return from ECALL.
    cmp $0, %rax
    jne .return_from_ecall_sim

    // (RDI=TCS, RDX=ARG1, RCX=ARG2)
    mov %rdx, ARG1
    mov %rcx, ARG2
    jmp .call_oe_main

.return_from_ecall_sim:

    // Set output parameters:
    mov %rdi, (%r8) /* arg3 */
    mov %rsi, (%r9) /* arg4 */

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
