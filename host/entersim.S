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

.globl OE_EnterSim
.type OE_EnterSim, @function
OE_EnterSim:
.cfi_startproc

    // Setup stack frame:
    push %rbp
    mov %rsp, %rbp

    // Save registers:
    push %rbx

    // Call OE_Main(RAX=CSSA, RBX=TCS, RCX=RETADDR, RDI=ARG1, RSI=ARG2)
    mov $0, %rax        // RAX=CSSA
    mov %rdi, %rbx      // RBX=TCS
    mov %rdx, %rdi      // RDI=ARG1
    mov %rcx, %rsi      // RSI=ARG2
    lea .retaddr, %rcx  // RCX=RETADDR
    mov 72(%rbx), %rdx  // RDX=TCS.u.main (72)
    jmp *%rdx

.retaddr:

    // Set output parameters:
    mov %rdi, (%r8) /* arg3 */
    mov %rsi, (%r9) /* arg4 */

    // Restore registers:
    pop %rbx

    // Restore stack frame:
    pop %rbp

    ret

.forever:
    jmp .forever

.cfi_endproc
