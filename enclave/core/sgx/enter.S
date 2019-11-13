// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "asmdefs.h"
#include <openenclave/internal/context.inc>
#include "asmcommon.inc"

//==============================================================================
//
// oe_enter(RAX=CSSA, RBX=TCS, RCX=RETADDR, RDI=ARG1, RSI=ARG2)
//
//     The EENTER instruction (executed by the host) calls this function to
//     enter the enclave.
//
//     Registers from EENTER:
//         RAX - index of current SSA (CSSA)
//         RBX - address of TCS (TCS)
//         RCX - address of instruction following EENTER (RETADDR)
//
//     Registers from host caller of EENTER:
//         RDI - ARG1
//         RSI - ARG2
//
//     This function performs the following tasks:
//
//         (1) Saves the host registers
//         (2) Calculates the enclave stack base
//         (3) Sets up the enclave stack frame
//         (4) Calls __oe_handle_main()
//
//     Note: __oe_handle_main does not return. Instead it eventually
//     calls oe_asm_exit (see exit.S)
//
//==============================================================================

.globl oe_enter
.type oe_enter, @function
oe_enter:
.cfi_startproc

.save_host_registers:
    mov %r8, %gs:td_host_eexit_frame

    // Backup the current host rbp and rsp to previous.
    mov %gs:td_host_rbp, %r8
    mov %r8, %gs:td_host_previous_rbp
    mov %gs:td_host_rsp, %r8
    mov %r8, %gs:td_host_previous_rsp

    // Save host registers (restored on EEXIT)
    mov %rcx, %gs:td_host_rcx // host return address here
    mov %rsp, %gs:td_host_rsp
    mov %rbp, %gs:td_host_rbp

.determine_entry_type:
    // Check if this is exception dispatching request.
    // exception-dispatching-request-check
    cmp $0, %rax
    jne .exception_entry

    // Stop speculative execution at fallthrough of conditional
    // exception-dispatching-request-check.
    lfence

    // Check whether this is a clean entry or a nested entry
    // clean-entry-check.
    mov %gs:td_depth, %r8
    cmp $0, %r8
    je .clean_entry
    jmp .nested_entry

.exception_entry:
    // Stop speculative execution at target of conditional jump
    // after exception-dispatching-request-check.
    lfence

    // Get the first ssa address from tcs.
    lea OE_SSA_FROM_TCS_BYTE_OFFSET(%rbx), %r10

    // Get the offset of current SSA from the begining of the SSA.
    dec %rax
    shl $0x0c, %rax

    // Get the address of current SSA.
    add %r10, %rax

    // Get the saved rsp. We can't depend on the TLS value to get the enclave rsp in exception entry since the value may
    // not be set correctly.
    mov SGX_SSA_RSP_OFFSET(%r10), %rsp

    // align stack.
    and $-16, %rsp

    // Start the new stack under the red zone.
    sub $ABI_REDZONE_BYTE_SIZE, %rsp
    jmp .call_function

.nested_entry:
    // Stop speculative execution at fallthrough of conditional
    // clean-entry-check.
    lfence

    // Restore stack pointer and enclave registers:
    mov %gs:td_last_sp, %rsp

    // align the stack
    and $-16, %rsp

    // Start the new stack under the red zone.
    sub $ABI_REDZONE_BYTE_SIZE, %rsp
    jmp .call_function

.clean_entry:
    // Stop speculative execution at target of conditional jump
    // after clean-entry-check.
    lfence

    // Calculate stack base relative to TCS (subtract guard page size)
    mov %rbx, %rsp
    sub $PAGE_SIZE, %rsp
    mov %rsp, %rbp

.call_function:
    // Set the MXCSR according to the Linux x86_64 ABI
    mov $ABI_MXCSR_INIT, %r10
    push %r10
    ldmxcsr (%rsp)
    pop %r10

    // Set the FPU Control Word according to the Linux x86_64 ABI
    mov $ABI_FPUCW_INIT, %r10
    push %r10
    fldcw (%rsp)
    pop %r10

    // Initialize the RFLAGS prior to calling enclave functions
    // This only clears the DF and state flag bits since
    // the system flags and reserved bits are not writable here
    push $0
    popfq

    // Get the host stack pointer.
    mov %gs:td_host_rsp, %r8
    mov %gs:td_host_rbp, %r9

    // Construct the frame and align the stack.
    pushq $0
    pushq %r8
    pushq %rcx
    pushq %r9
.cfi_def_cfa_offset     16
.cfi_offset             rbp, -16
    mov %rsp, %rbp
.cfi_def_cfa_register   rbp

#define OM_STACK_LENGTH             0X30
#define OM_HOST_RSP                 (-1*8)(%rbp)
#define OM_HOST_RBP                 (-2*8)(%rbp)
#define OM_HOST_OUTPUT_ARG1         (-3*8)(%rbp)
#define OM_HOST_OUTPUT_ARG2         (-4*8)(%rbp)
#define OM_HOST_RETURN_ADDR         (-5*8)(%rbp)

    // Allocate stack.
    sub $OM_STACK_LENGTH, %rsp

    // Save the host stack pointers to enclave stack.
    mov %gs:td_host_rsp, %r8
    mov %gs:td_host_rbp, %r9
    mov %r8, OM_HOST_RSP
    mov %r9, OM_HOST_RBP

    // Save the host return address to enclave stack.
    mov %gs:td_host_rcx, %r8
    mov %r8, OM_HOST_RETURN_ADDR

    // Call __oe_handle_main(ARG1=RDI, ARG2=RSI, CSSA=RDX, TCS=RCX, OUTPUTARG1=R8, OUTPUTARG2=R9)
    mov %rax, %rdx
    mov %rbx, %rcx
    lea OM_HOST_OUTPUT_ARG1, %r8
    lea OM_HOST_OUTPUT_ARG2, %r9
    call __oe_handle_main

    // Get the output parameters.
    mov OM_HOST_OUTPUT_ARG1, %rdi
    mov OM_HOST_OUTPUT_ARG2, %rsi

.determine_exit_type:

    // Check the depth of the ECALL stack (zero for clean exit)
    // exit-type-check.
    mov %gs:td_depth, %r8
    cmp $0, %r8
    je .clean_exit

.nested_exit:
    // Stop speculative execution at fallthrough of conditional
    // exit-type-check.
    lfence

    // Construct the oe_ocall_context_t(rbp, return address).
    mov (4*OE_WORD_SIZE)(%rsp), %r12
    push %r12
    push %rbp
    mov %rsp, %r12

    // Save the parameters of oe_asm_exit into stack.
    push %rdi
    push %rsi

    // Notify a nested exit happens.
    // oe_notify_nested_exit_start(rdi=arg1, rsi=ocall_context)
    mov %r12, %rsi
    call oe_notify_nested_exit_start

    // Restore the parameters of oe_asm_exit from stack.
    pop %rsi
    pop %rdi

    // Restore the stack to correct status: rbp/rsp should not change after function call.
    pop %r12
    pop %r12

    mov %rsp, %gs:td_last_sp

    jmp .clear_enclave_registers

.clean_exit:
    // Stop speculative execution at target of conditional jump
    // after exit-type-check.
    lfence

    // Clear the td_t.last_sp field (force oe_enter to calculate stack pointer)
    movq $0, %gs:td_last_sp

.clear_enclave_registers:

    // Clear these so information will not be leaked to host
    oe_cleanup_registers

.restore_host_registers:

    mov OM_HOST_RETURN_ADDR, %rcx
    mov OM_HOST_RETURN_ADDR, %rbx
    mov OM_HOST_RSP, %rsp
    mov OM_HOST_RBP, %rbp

.execute_eexit:

    // Check td_t.simulate flag
    // simulation-flag-check.
    mov %gs:td_simulate, %rax
    cmp $0, %rax
    jz .execute_eexit_instruction

.execute_eexit_sim:
    // Stop speculative execution at fallthrough of conditional
    // simulate-flag-check.
    lfence

    // Jump to return address:
    mov $1, %rax
    jmp *%rcx
    ud2

.execute_eexit_instruction:
    // Stop speculative execution at target of conditional jump
    // simulate-flag-check.
    lfence

    // EEXIT(RAX=EEXIT, RBX=RETADDR, RCX=AEP, RDI=ARG1, RSI=ARG2)
    //mov %rcx, %rbx
    mov $ENCLU_EEXIT, %rax
    ENCLU
    ud2

.forever:
    jmp .forever

.cfi_endproc

.size oe_enter, .-oe_enter

//==============================================================================
//
// void oe_exception_dispatcher(void)
//
// Routine Description:
//
//   This function is used to dispatch an enclave exception.
//
//  Arguments:
//      None.
//
//  Return value:
//      None.
//==============================================================================

#define SIZEOF_OE_CONTEXT 0X2A0
#define ED_STACK_LENGTH SIZEOF_OE_CONTEXT + 0x20
#define ED_OE_CONTEXT        (%rsp)
#define ED_SAVED_RDI         (0*8)(%rbp)
#define ED_SAVED_RBP         (1*8)(%rbp)
#define ED_SAVED_RSP         (2*8)(%rbp)

.globl oe_exception_dispatcher
.type oe_exception_dispatcher, @function
oe_exception_dispatcher:
.cfi_startproc
    // Start the new stack under the red zone.
    sub $ABI_REDZONE_BYTE_SIZE, %rsp

    // Save the registers that will be clobbered before snap context is called.
    push %rsp
    push %rbp
    push %rdi
    mov %rsp, %rbp

    // align the stack.
    and $-16, %rsp

    // Allocate stack.
    sub $ED_STACK_LENGTH, %rsp

    // Recapture the context of exception. The output context is all correct except:
    // rbp, rsp, rdi, and rip.
    lea ED_OE_CONTEXT, %rdi
    call oe_snap_current_context

    // Restore the previous rbp to rbp of OE_CONTEXT.
    lea ED_OE_CONTEXT, %rdi
    movq ED_SAVED_RBP, %rax
    movq %rax, OE_CONTEXT_RBP(%rdi)

    // Restore the previous rsp to rsp of OE_CONTEXT.
    movq ED_SAVED_RSP, %rax
    add $ABI_REDZONE_BYTE_SIZE, %rax
    movq %rax, OE_CONTEXT_RSP(%rdi)

    // Restore the previous rdi to rdi of OE_CONTEXT.
    movq ED_SAVED_RDI, %rax
    movq %rax, OE_CONTEXT_RDI(%rdi)

    call oe_real_exception_dispatcher

    // Should never reach here since oe_real_exception_dispatcher will not return.

.forever_loop:
    jmp .forever_loop
.cfi_endproc

.size oe_exception_dispatcher, .-oe_exception_dispatcher
