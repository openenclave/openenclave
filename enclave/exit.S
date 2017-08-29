#include "asmdefs.h"

//==============================================================================
//
// void OE_Exit(uint64_t arg1, uint64_t arg2)
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
//          thread data structure (TD.last_sp)
//
//      (3) If this a clean exit, then store zero in TD.last_sp, forcing
//          OE_Main() to recompute it on next entry.
//
//      (4) Clear enclave registers to avoid leaking data to the host.
//
//      (5) Restore the host registers from the thread data structure
//          (TD).
//
//      (6) Execute the SGX EEXIT instruction, exiting the enclave and
//          returning control to the host.
//
//==============================================================================

.globl OE_Exit
.type OE_Exit, @function
OE_Exit:
.cfi_startproc

.determine_exit_type:

    // Check the depth of the ECALL stack (zero for clean exit)
    mov %gs:TD_depth, %r8
    cmp $0, %r8
    je .clean_exit

.nested_exit:

    // Save host registers and stack pointer (will be restored on reentry)
    push %r12
    push %r13
    push %r14
    push %r15
    mov %rsp, %gs:TD_last_sp

    jmp .clear_enclave_registers

.clean_exit:

    // Clear the TD.last_sp field (force OE_Main to calculate stack pointer)
    movq $0, %gs:TD_last_sp

.clear_enclave_registers:

    // Clear these so information will not be leaked to host
    xor %rcx, %rcx
    xor %rdx, %rdx
    xor %r8,  %r8
    xor %r9,  %r9
    xor %r10, %r10
    xor %r11, %r11
    xor %r12, %r12
    xor %r13, %r13
    xor %r14, %r14
    xor %r15, %r15

    // Reset status flags
    add %rdx, %rdx 

.restore_host_registers:

    mov %gs:TD_host_rcx, %rcx
    mov %gs:TD_host_rdx, %rdx
    mov %gs:TD_host_r8,  %r8
    mov %gs:TD_host_r9,  %r9
    mov %gs:TD_host_r10, %r10
    mov %gs:TD_host_r11, %r11
    mov %gs:TD_host_r12, %r12
    mov %gs:TD_host_r13, %r13
    mov %gs:TD_host_r14, %r14
    mov %gs:TD_host_r15, %r15
    mov %gs:TD_host_rsp, %rsp
    mov %gs:TD_host_rbp, %rbp

.execute_eexit:

    // Check TD.simulate flag
    mov %gs:TD_simulate, %rax
    cmp $0, %rax
    jz .execute_eexit_instruction

.execute_eexit_sim:

    // Jump to return address:
    mov $1, %rax
    jmp *%rcx
    ud2

.execute_eexit_instruction:

    // EEXIT(RAX=EEXIT, RBX=RETADDR, RCX=AEP, RDI=ARG1, RSI=ARG2)
    mov %rcx, %rbx
    mov $ENCLU_EEXIT, %rax
    ENCLU
    ud2

.forever:
    jmp .forever

.cfi_endproc
