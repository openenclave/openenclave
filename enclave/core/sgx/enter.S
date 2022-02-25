// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "asmdefs.h"
#include "asmcommon.inc"
#include "context.inc"

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
//         RDX - HOST ECALL CONTEXT
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

.get_td:

    // Get the location of the td_t structure for this thread. This value is
    // expected to be present in %r11 for the remainder of oe_enter.
    //
    // Upon first entry to the enclave, td->base.self in the td_t structure
    // is not yet initialized. However, the loader in host/sgx/create.c places
    // the td_t structure as a specific offset from TCS.
    mov _td_from_tcs_offset(%rip), %r11
    add %rbx, %r11

.check_aborted:
    cmpq $TD_STATE_ABORTED, td_state(%r11)
    je .abort

    // Get the first ssa address from tcs
    lea OE_SSA_FROM_TCS_BYTE_OFFSET(%rbx), %r10

.save_host_registers:
    // Backup the current ecall context to previous
    mov td_host_ecall_context(%r11), %r8
    mov %r8, td_host_previous_ecall_context(%r11)

    // Save host registers (restored on EEXIT)
    mov %rax, td_eenter_rax(%r11) // cssa set by EENTER
    mov %rcx, td_host_rcx(%r11) // host return address here
    mov %rdx, td_host_ecall_context(%r11)

.determine_entry_type:
    // Check if this is exception dispatching request
    // Return on the eenter if cssa greater than one, which
    // should not occur because OE assumes the enclave with nssa=2
    cmp $1, %rax
    je .exception_entry
    ja .return

    // Stop speculative execution at fallthrough of conditional
    // exception-dispatching-request-check.
    lfence

.update_td_state_on_normal_entry:
    // Do not update the state if the enclave enters in the middle
    // the exception handling (e.g., making an ocall)
    cmpq $TD_STATE_SECOND_LEVEL_EXCEPTION_HANDLING, td_state(%r11)
    je .check_entry_nesting_level

    // Update state and clear previous state on normal entries
    movq $TD_STATE_NULL, td_previous_state(%r11)
    movq $TD_STATE_ENTERED, td_state(%r11)

.check_entry_nesting_level:
    lfence
    // Check whether this is a clean entry or a nested entry
    // clean-entry-check.
    mov td_depth(%r11), %r8
    cmp $0, %r8
    je .clean_entry
    jmp .nested_entry

.exception_entry:
    // Stop speculative execution at target of conditional jump
    // after exception-dispatching-request-check.
    lfence

    // Abort if SSA[0].GPRSGX.RSP equals to SSA[0].GPRSGX.URSP
    mov SGX_SSA_RSP_OFFSET(%r10), %r8
    mov SGX_SSA_URSP_OFFSET(%r10), %r9
    cmp %r8, %r9
    je .return

    // Calculate the base address of the enclave
    lea _enclave_rva(%rip), %r12
    mov (%r12), %r13
    sub %r13, %r12

    // Calculate the end of the enclave address (base + enclave_size)
    lea oe_enclave_properties_sgx(%rip), %r13
    mov OE_SGX_ENCLAVE_SIZE_OFFSET(%r13), %r13
    add %r12, %r13

    // Abort if SSA[0].GPRSGX.URSP is within the enclave memory range
    cmp %r12, %r9
    jb .exception_handler_stack_check
    cmp %r13, %r9
    jae .exception_handler_stack_check
    jmp .return

    // Reaching this point implies SSA[0].GPRSGX.RSP is within the enclave
    // memory range so we do not need additional checks.

.exception_handler_stack_check:
    // Stop speculative execution at target of conditional jump
    lfence

    // Get the exception_handler_stack_check range
    mov td_exception_handler_stack(%r11), %r14
    mov td_exception_handler_stack_size(%r11), %r15
    test %r15, %r15
    jz .exception_stack_setup // check if size is zero
    add %r14, %r15
    jc .exception_stack_setup // check for overflow

    // Check if the stack range is within the enclave memory range
    // If the check fails, fallback to the default behavior (i.e.,
    // re-using the stack pointer saved in the SSA)
    cmp %r12, %r14
    jb .exception_stack_setup
    cmp %r13, %r15
    ja .exception_stack_setup

    // Check passes, use the exception handler stack
    mov %r15, %r8

    // Align the stack
    and $-16, %r8

    // Proceed without the red zone
    jmp .state_machine_check

.exception_stack_setup:
    // Stop speculative execution at target of conditional jump
    lfence

    // Align the stack
    and $-16, %r8

    // Start the new stack under the red zone
    sub $ABI_REDZONE_BYTE_SIZE, %r8

.state_machine_check:
    cmpq $0, td_exception_nesting_level(%r11)
    jne .state_machine_check_nested_exception

.state_machine_check_non_nested_exception:
    // Expect the state to be RUNNING on a non-nested exception
    // entry
    cmpq $TD_STATE_RUNNING, td_state(%r11)
    jne .return
    jmp .check_host_signal_request

.state_machine_check_nested_exception:
    lfence
    // Expect the state to be SECOND_LEVEL_EXCEPTION_HANDLING
    // on a nested exception entry
    cmpq $TD_STATE_SECOND_LEVEL_EXCEPTION_HANDLING, td_state(%r11)
    jne .return

.check_host_signal_request:
    movq td_state(%r11), %r12

    // Input value falls in the range of [1, 64] indicates
    // a host signal request
    cmp $0, %rsi
    je .update_td_state
    cmp $MAX_SIGNAL_NUMBER, %rsi
    ja .update_td_state

    // Proceed if the host_signal_unmasked flag is set
    cmpq $1, td_host_signal_unmasked(%r11)
    jne .return

    // Proceed if the corresponding bit of the signal
    // (i.e., signal number - 1) is set in the bitmask
    mov td_host_signal_bitmask(%r11), %r13
    mov %rsi, %r14
    dec %r14
    bt %r14, %r13
    jnc .return

    // Proceed only if the state is RUNNING
    cmp $TD_STATE_RUNNING, %r12
    jne .return

    // Proceed if the thread is currently not handling a host signal
    cmpq $1, td_is_handling_host_signal(%r11)
    je .return

    // Proceed if the exception entry is not nested
    cmpq $0, td_exception_nesting_level(%r11)
    jne .return

    lfence

    // Set the flag if the request is accepted
    movq $1, td_is_handling_host_signal(%r11)

    // Store the host-passed signal number
    mov %rsi, td_host_signal(%r11)

.update_td_state:
    lfence

    // Keep the state before the exception so that we can restore the
    // state in the illegal instruction emulation flow
    mov %r12, td_previous_state(%r11)
    movq $TD_STATE_FIRST_LEVEL_EXCEPTION_HANDLING, td_state(%r11)

    // Increase the nesting level, which will be decreased before resuming
    // the execution (see exception.c)
    incq td_exception_nesting_level(%r11)
    jmp .call_function

.nested_entry:
    // Stop speculative execution at fallthrough of conditional
    // clean-entry-check.
    lfence

    // Restore stack pointer and enclave registers:
    mov td_last_sp(%r11), %r8

    // align the stack
    and $-16, %r8

    // Start the new stack under the red zone.
    sub $ABI_REDZONE_BYTE_SIZE, %r8
    jmp .call_function

.clean_entry:
    // Stop speculative execution at target of conditional jump
    // after clean-entry-check.
    lfence

    // Calculate stack base relative to TCS (subtract guard page size)
    mov %rbx, %r8
    sub $PAGE_SIZE, %r8

.call_function:
    // Stop speculative execution for the fallthrough cases
    lfence

    // Set the rsp to the in-enclave stack
    mov %r8, %rsp

    cmp $1, %rax
    je .locate_next_ssa
    jmp .construct_stack_frame

.locate_next_ssa:
    // Stop speculative execution at fallthrough of conditional
    // rax (cssa) check.
    lfence

    add $PAGE_SIZE, %r10

.construct_stack_frame:
    // Get the host stack pointer from SSA
    mov SGX_SSA_URSP_OFFSET(%r10), %r8
    mov SGX_SSA_URBP_OFFSET(%r10), %r9

    // Construct the frame and align the stack
    pushq $0
    pushq %r8
    pushq %rcx
    pushq %r9
.cfi_def_cfa_offset     16
.cfi_offset             rbp, -16
    mov %rsp, %rbp
.cfi_def_cfa_register   rbp

// 16-byte alignment
#define OM_STACK_LENGTH             0X20
#define OM_HOST_OUTPUT_ARG1         (-1*8)(%rbp)
#define OM_HOST_OUTPUT_ARG2         (-2*8)(%rbp)
#define OM_ENC_TD                   (-3*8)(%rbp)

    // Allocate stack.
    sub $OM_STACK_LENGTH, %rsp

    // Save reference to the td structure to enclave stack.
    mov %r11, OM_ENC_TD

    // Clear the XSTATE so that enclave has clean legacy SSE and extended states
    xor %r11, %r11
    oe_cleanup_registers

    // Call __oe_handle_main(ARG1=RDI, ARG2=RSI, CSSA=RDX, TCS=RCX, OUTPUTARG1=R8, OUTPUTARG2=R9)
    mov %rax, %rdx
    mov %rbx, %rcx
    lea OM_HOST_OUTPUT_ARG1, %r8
    lea OM_HOST_OUTPUT_ARG2, %r9
    call __oe_handle_main

    // Get the output parameters.
    mov OM_HOST_OUTPUT_ARG1, %rdi
    mov OM_HOST_OUTPUT_ARG2, %rsi

    // Restore td pointer
    mov OM_ENC_TD, %rdx
    // Set the argument aborting=0 for oe_asm_exit
    xor %rcx, %rcx
    jmp .eexit

.abort:
    lfence

    // Set argument 2 for oe_asm_exit
    mov $CODE_ENCLAVE_ABORTING, %rsi

    // Update the global enclave status
    mov %rsi, __oe_enclave_status(%rip)

    jmp .prepare_eexit

.return:
    lfence

    // Set argument 2 for oe_asm_exit
    mov $CODE_EXCEPTION_CONTINUE_EXECUTION, %rsi

.prepare_eexit:
#define ARG1_CODE_ERET        0x2 // OE_CODE_ERET in oe_code_t
#define ARG1_CODE_BIT_OFFSET  0x30 // Refer to oe_make_call_arg1 in calls.h

    // Set argument 1 for oe_asm_exit
    mov $ARG1_CODE_ERET, %rdi
    shl $ARG1_CODE_BIT_OFFSET, %rdi
    mov %r11, %rdx
    mov $1, %rcx // direct_return=1

.eexit:
    // Invoke oe_asm_exit with (ARG1=RDI, ARG2=RSI, TD=RDX, ABORTING=RCX)
    jmp oe_asm_exit

    // Should never reach here because oe_asm_exit does not return

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

    // Dummy operations to ensure the red zone does not bypass the guard page.
    // This could happen when setting the exception handler stack but not
    // registering the stack for #PF. In this case, when the stack overflow
    // occurs, the first-stage handler will use the exception handler stack and
    // then continue the execution to this point with the corrupted stack,
    // pointing to near the end of the guard page.
    push %rbp
    pop %rbp

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
