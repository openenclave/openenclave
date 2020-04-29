// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "asmdefs.h"
#include "asmcommon.inc"

//==============================================================================
//
// void oe_asm_exit(uint64_t arg1, uint64_t arg2)
//
// Registers:
//     RDI - arg1
//     RSI - arg2
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

.determine_exit_type:

    // Check the depth of the ECALL stack (zero for clean exit)
    // exit-type-check.
    mov %fs:td_depth, %r8
    cmp $0, %r8
    je .clean_exit

.nested_exit:
    // Stop speculative execution at fallthrough of conditional
    // exit-type-check.
    lfence 

    mov %rsp, %fs:td_last_sp

    jmp .clear_enclave_registers

.clean_exit:
    // Stop speculative execution at target of conditional jump
    // after exit-type-check.
    lfence

    // Clear the oe_sgx_td_t.last_sp field (force oe_enter to calculate stack pointer)
    movq $0, %fs:td_last_sp

.clear_enclave_registers:

    // Clear these so information will not be leaked to host
    oe_cleanup_registers

.restore_host_registers:

    mov %fs:td_host_rcx, %rcx
    mov %fs:td_host_rsp, %rsp
    mov %fs:td_host_rbp, %rbp

.execute_eexit:

    // Check oe_sgx_td_t.simulate flag
    // simulate-flag-check.
    mov %fs:td_simulate, %rax
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
    // after simulate-flag-check.
    lfence
    
    // EEXIT(RAX=EEXIT, RBX=RETADDR, RCX=AEP, RDI=ARG1, RSI=ARG2)
    mov %rcx, %rbx
    mov $ENCLU_EEXIT, %rax
    ENCLU
    ud2

.forever:
    jmp .forever

.cfi_endproc
