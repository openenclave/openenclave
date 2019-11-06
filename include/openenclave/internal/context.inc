// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/constants_x64.h>

//==============================================================================
//
// void oe_snap_current_context(OE_CONTEXT * oe_context)
//
// Routine Description:
//
// This function captures the context of the caller. All register values except
// the rip are exactly same as the values before this function call instruction
// is executed. The rip in the output context is set to the return address of 
// this function.
//
// Arguments:
//     oe_context(rdi): The output context.
//
// Return value:
//     None.
//==============================================================================

.globl oe_snap_current_context
.type oe_snap_current_context, @function
oe_snap_current_context:
.cfi_startproc
    // Save the flags to stack.
    pushfq

    // Get general registers.
    // Save rax, rbx, rcx, rdx.
    movq    %rax, OE_CONTEXT_RAX(%rdi)
    movq    %rbx, OE_CONTEXT_RBX(%rdi)
    movq    %rcx, OE_CONTEXT_RCX(%rdi)
    movq    %rdx, OE_CONTEXT_RDX(%rdi)

    // Save rbp and rsp.
    movq    %rbp, OE_CONTEXT_RBP(%rdi)
    movq    %rsp, %rax
    addq    $0x10, %rax
    movq    %rax, OE_CONTEXT_RSP(%rdi)

    // Save rsi and rdi.
    movq    %rdi, OE_CONTEXT_RDI(%rdi)
    movq    %rsi, OE_CONTEXT_RSI(%rdi)

    // Save r8, r9 ... r15.
    movq    %r8, OE_CONTEXT_R8(%rdi)
    movq    %r9, OE_CONTEXT_R9(%rdi)
    movq    %r10, OE_CONTEXT_R10(%rdi)
    movq    %r11, OE_CONTEXT_R11(%rdi)
    movq    %r12, OE_CONTEXT_R12(%rdi)
    movq    %r13, OE_CONTEXT_R13(%rdi)
    movq    %r14, OE_CONTEXT_R14(%rdi)
    movq    %r15, OE_CONTEXT_R15(%rdi)

    // Save rip.
    movq    %rsp, %rax
    addq    $0x8, %rax
    movq    (%rax), %rbx
    movq    %rbx, OE_CONTEXT_RIP(%rdi)

    // Save SSE control flags.
    stmxcsr OE_CONTEXT_MXCSR(%rdi)

    // Save x87 and SSE values.
    fxsave  OE_CONTEXT_FLOAT(%rdi)

    // Save the flags
    movq    (%rsp), %rax
    movq    %rax, OE_CONTEXT_FLAGS(%rdi)

    // Restore the flags
    popfq

    // Return
    retq
.cfi_endproc

//==============================================================================
//
// This macro is used to restore the X87, SSE, rax, rbx, rcx, rdx, rsi, and r8,
// r9 ... r15
//
//==============================================================================
.macro restore_common_registers
    // Restore the x87 and SSE values.
    fxrstor OE_CONTEXT_FLOAT(%rdi)

    // Restore SSE control flags.
    ldmxcsr OE_CONTEXT_MXCSR(%rdi)

    // Restore general registers.
    // Restore rax, rbx, rcx, rdx.
    movq    OE_CONTEXT_RAX(%rdi), %rax
    movq    OE_CONTEXT_RBX(%rdi), %rbx
    movq    OE_CONTEXT_RCX(%rdi), %rcx
    movq    OE_CONTEXT_RDX(%rdi), %rdx

    // Restore rsi.
    movq    OE_CONTEXT_RSI(%rdi), %rsi

    // Restore r8, r9 ... r15.
    movq    OE_CONTEXT_R8(%rdi), %r8
    movq    OE_CONTEXT_R9(%rdi), %r9
    movq    OE_CONTEXT_R10(%rdi), %r10
    movq    OE_CONTEXT_R11(%rdi), %r11
    movq    OE_CONTEXT_R12(%rdi), %r12
    movq    OE_CONTEXT_R13(%rdi), %r13
    movq    OE_CONTEXT_R14(%rdi), %r14
    movq    OE_CONTEXT_R15(%rdi), %r15
.endm

//==============================================================================
//
// void oe_restore_partial_context(OE_CONTEXT * oe_context)
//
// Routine Description:
//
//   This function restore following partial context in the specified context
//   record.
//       1. GPR excluding RIP, RSP and RBP.
//       2. X87, SSE.
//       3. Flags.
//
// Arguments:
//
//    oe_context (rdi) - Supplies a pointer to a context record.
//
// Return Value:
//
//    None.
//
//==============================================================================

.globl oe_restore_partial_context
.type oe_restore_partial_context, @function
oe_restore_partial_context:
.cfi_startproc
    restore_common_registers

    // Push the saved flags to stack.
    pushq   OE_CONTEXT_FLAGS(%rdi)

    // Restore rdi.
    movq    OE_CONTEXT_RDI(%rdi), %rdi

    // Restore flags.
    popfq

    // Return
    retq
.cfi_endproc

//==============================================================================
//
// void oe_continue_execution(OE_CONTEXT * oe_context)
//
// Routine Description:
//
//   This function restores the full oe_context, and continue run on the rip of
//   input context.
//
// Arguments:
//
//    oe_context (rdi) - Supplies a pointer to a context record.
//
// Return Value:
//
//    None. This function will not return to caller.
//
//==============================================================================

.globl oe_continue_execution
.type oe_continue_execution, @function
oe_continue_execution:
.cfi_startproc
    restore_common_registers

    // Restore rbp, rsp
    movq    OE_CONTEXT_RBP(%rdi), %rbp
    movq    OE_CONTEXT_RSP(%rdi), %rsp

    // Put local variables under the red zone.
    sub     $ABI_REDZONE_BYTE_SIZE, %rsp

    // Push the target address to stack.
    pushq   OE_CONTEXT_RIP(%rdi)

    // Push the saved flags to stack.
    pushq   OE_CONTEXT_FLAGS(%rdi)

    // Restore rdi.
    movq    OE_CONTEXT_RDI(%rdi), %rdi

    // Restore flags.
    popfq

    // Recovery the correct rsp.
    add     $(ABI_REDZONE_BYTE_SIZE + 8), %rsp

    // Jump to the target.
    jmp     *-(ABI_REDZONE_BYTE_SIZE + 8)(%rsp)
.cfi_endproc
