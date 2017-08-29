#include "asmdefs.h"

//==============================================================================
//
// void OE_Enter(
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
//==============================================================================

.globl OE_Enter
.type OE_Enter, @function
OE_Enter:
.cfi_startproc

    // Setup stack frame:
    push %rbp
    mov %rsp, %rbp

    // Save registers:
    push %rbx

    // EENTER(RBX=TCS, RCX=AEP, RDI=ARG1, RSI=ARG2)
    mov %rdi, %rbx
    mov %rdx, %rdi
    xchg %rsi, %rcx
    mov $ENCLU_EENTER, %rax
    ENCLU

    // Set output parameters:
    mov %rdi, (%r8) /* arg3 */
    mov %rsi, (%r9) /* arg4 */

    // Restore registers:
    pop %rbx

    // Restore stack frame:
    pop %rbp

    ret

.cfi_endproc
