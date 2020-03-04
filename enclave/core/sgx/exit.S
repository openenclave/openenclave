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
//          thread data structure (td_t.last_sp)
//
//      (3) If this a clean exit, then store zero in td_t.last_sp, forcing
//          oe_enter() to recompute it on next entry.
//
//      (4) Clear enclave registers to avoid leaking data to the host.
//
//      (5) Restore the host registers from the thread data structure
//          (td_t).
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

    // Save argument registers
    push %rdi
    push %rsi

    // Get a pointer to the td structure. This value is expected to be present
    // in %r9 for the remainder of oe_asm_exit
    call oe_get_td
    mov %rax, %r9

    // Restore argument registers
    pop %rsi
    pop %rdi

.determine_exit_type:

    // Check the depth of the ECALL stack (zero for clean exit)
    // exit-type-check.
    mov td_depth(%r9), %r8
    cmp $0, %r8
    je .clean_exit

.nested_exit:
    // Stop speculative execution at fallthrough of conditional
    // exit-type-check.
    lfence 

    mov %rsp, td_last_sp(%r9)

    jmp .clear_enclave_registers

.clean_exit:
    // Stop speculative execution at target of conditional jump
    // after exit-type-check.
    lfence

    // Clear the td_t.last_sp field (force oe_enter to calculate stack pointer)
    movq $0, td_last_sp(%r9)

.clear_enclave_registers:

    // Clear registers so information will not be leaked to host
    // Retain %r11 which is used to reference the td structure. It will be
    // cleared immediately before EEXIT.
    push %r9
    oe_cleanup_registers
    pop %r9

.restore_host_registers:

    mov td_host_rcx(%r9), %rcx
    mov td_host_rsp(%r9), %rsp
    mov td_host_rbp(%r9), %rbp

.execute_eexit:

    // Check td_t.simulate flag
    // simulate-flag-check.
    mov td_simulate(%r9), %rax
    cmp $0, %rax
    jz .execute_eexit_instruction

.execute_eexit_sim:
    // Stop speculative execution at fallthrough of conditional
    // simulate-flag-check.
    lfence

    // Clear %r9 which was being used to maintain td pointer
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
