// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "asmdefs.h"
#include "asmcommon.inc"
#include <openenclave/internal/constants_x64.h>

//==============================================================================
//
// void oe_asm_exit(uint64_t arg1, uint64_t arg2, oe_sgx_td_t* td, uint64_t direct_return)
//
// Registers:
//     RDI - arg1
//     RSI - arg2
//     RDX - td
//     RCX - direct_return
//
// Purpose:
//     Restores user registers and executes the EEXIT instruction to leave the
//     enclave and return control to the host. This function is called for two
//     reasons:
//
//         (1) To perform an ERET (ECALL return)
//         (2) To perform an OCALL
//
// Tasks:
//
//      (1) Determines whether the caller is performing a "clean exit"
//          or a "nested exit". ECALLs and OCALLs can be nested so
//          we define DEPTH as the number of ECALL stack frames. A
//          DEPTH of zero indicates no ECALL stack frames remain and
//          that no ECALLs are pending.
//
//      (2) If this is a nested exit, then save the enclave registers
//          on the enclave stack and save the stack pointer in the
//          thread data structure (oe_sgx_td_t.last_sp)
//
//      (3) If this a clean exit, then store zero in oe_sgx_td_t.last_sp, forcing
//          oe_enter() to recompute it on next entry.
//
//      (4) Clear enclave registers to avoid leaking data to the host.
//
//      (5) Restore the host registers from the thread data structure
//          (oe_sgx_td_t).
//
//      (6) Execute the SGX EEXIT instruction, exiting the enclave and
//          returning control to the host.
//
//==============================================================================

.globl oe_asm_exit
.hidden oe_asm_exit
.type oe_asm_exit, @function
oe_asm_exit:
.cfi_startproc

.get_td:
    mov %rdx, %r11

.determine_exit_type:
    // Save the direct_return argument in r13 and check if it is set
    mov %rcx, %r13
    cmp $1, %r13
    je .return

    // Check the depth of the ECALL stack (zero for clean exit)
    // exit-type-check.
    mov td_depth(%r11), %r8
    cmp $0, %r8
    je .clean_exit

.nested_exit:
    // Stop speculative execution at fallthrough of conditional
    // exit-type-check.
    lfence 

    mov %rsp, td_last_sp(%r11)
    jmp .prepare_eexit

.clean_exit:
    // Stop speculative execution at target of conditional jump
    // after exit-type-check.
    lfence

    // Clear the oe_sgx_td_t.last_sp field (force oe_enter to calculate stack pointer)
    movq $0, td_last_sp(%r11)
    jmp .prepare_eexit

.return:
    lfence

    // Restore host ecall context
    mov td_host_previous_ecall_context(%r11), %r8
    mov %r8, td_host_ecall_context(%r11)

.prepare_eexit:
    mov _td_from_tcs_offset(%rip), %r8
    mov %r11, %r9
    sub %r8, %r9 // td_to_tcs
    lea OE_SSA_FROM_TCS_BYTE_OFFSET(%r9), %r12
    mov td_eenter_rax(%r11), %r8
    cmp $1, %r8
    je .locate_next_ssa
    jmp .restore_host_registers

.locate_next_ssa:
    // Stop speculative execution at fallthrough of conditional
    // td_eenter_rax check.
    lfence

    add $PAGE_SIZE, %r12
    // Reset the saved cssa to zero to match the value on
    // the previous oe_enter (which ERESUME will return to)
    movq $0, td_eenter_rax(%r11)

.restore_host_registers:
    mov td_host_rcx(%r11), %rcx
    mov SGX_SSA_URSP_OFFSET(%r12), %rsp
    mov SGX_SSA_URBP_OFFSET(%r12), %rbp

    // Bypass update_td_state if direct_return is set
    cmp $1, %r13
    je .execute_eexit

.update_td_state:
    lfence

    // Do not update the state if the enclave exits in the middle
    // the exception handling (e.g., exiting from the first-level
    // exception handler), exits after an illegal instruction
    // emulation, or the enclave is aborted
    cmpq $TD_STATE_SECOND_LEVEL_EXCEPTION_HANDLING, td_state(%r11)
    je .execute_eexit
    cmpq $TD_STATE_FIRST_LEVEL_EXCEPTION_HANDLING, td_previous_state(%r11)
    je .execute_eexit
    cmpq $TD_STATE_ABORTED, td_state(%r11)
    je .execute_eexit

    lfence

    // Update the state to indicate that the enclave is returning
    // to the host
    movq $TD_STATE_EXITED, td_state(%r11)

.execute_eexit:
    oe_cleanup_registers

    // Check oe_sgx_td_t.simulate flag
    // simulate-flag-check.
    mov td_simulate(%r11), %rax
    cmp $0, %rax
    jz .execute_eexit_instruction

.execute_eexit_sim:
    // Stop speculative execution at fallthrough of conditional
    // simulate-flag-check.
    lfence

    // Clear %r11 which was being used to maintain td pointer
    xor %r11, %r11

    // Jump to return address:
    mov $1, %rax
    jmp *%rcx
    ud2

.execute_eexit_instruction:
    // Stop speculative execution at target of conditional jump
    // after simulate-flag-check.
    lfence

    // Clear %r9 which was being used to maintain td pointer
    xor %r11, %r11
    
    // EEXIT(RAX=EEXIT, RBX=RETADDR, RCX=AEP, RDI=ARG1, RSI=ARG2)
    mov %rcx, %rbx
    mov $ENCLU_EEXIT, %rax
    ENCLU
    ud2

.forever:
    jmp .forever

.cfi_endproc
