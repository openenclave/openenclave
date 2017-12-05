#include "asmdefs.h"

//==============================================================================
//
// OE_Main(RAX=CSSA, RBX=TCS, RCX=RETADDR, RDI=ARG1, RSI=ARG2)
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
//         (4) Calls __OE_HandleMain()
//
//     Note: __OE_HandleMain does not return. Instead it eventually
//     calls OE_Exit (see exit.S)
//
//==============================================================================

.globl OE_Main
.type OE_Main, @function
OE_Main:
.cfi_startproc

.save_host_registers:

    // Save host registers (restored on EEXIT)
    mov %rcx, %gs:TD_host_rcx // host return address here
    mov %rdx, %gs:TD_host_rdx
    mov %r8,  %gs:TD_host_r8
    mov %r9,  %gs:TD_host_r9
    mov %r10, %gs:TD_host_r10
    mov %r11, %gs:TD_host_r11
    mov %r12, %gs:TD_host_r12
    mov %r13, %gs:TD_host_r13
    mov %r14, %gs:TD_host_r14
    mov %r15, %gs:TD_host_r15
    mov %rsp, %gs:TD_host_rsp
    mov %rbp, %gs:TD_host_rbp
	
.determine_entry_type:

    // Check whether this is a clean entry or a nested entry
    mov %gs:TD_depth, %r8 
    cmp $0, %r8 
    je .clean_entry

.nested_entry:

    // Restore stack pointer and enclave registers:
    mov %gs:TD_last_sp, %rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12

    jmp .call_function

.clean_entry:

    // Calculate stack base relative to TCS (subtract guard page size)    
    mov %rbx, %rsp 
    sub $PAGE_SIZE, %rsp
    mov %rsp, %rbp

.call_function:

	// Get the host stack pointer.
	mov %gs:TD_host_rsp, %r8
	mov %gs:TD_host_rbp, %r9

	// Construct the frame and align the stack.
	pushq $0
	pushq %r8
	pushq %rcx
	pushq %r9
.cfi_def_cfa_offset		16
.cfi_offset				rbp, -16
	mov %rsp, %rbp
.cfi_def_cfa_register	rbp
	
    // Call __OE_HandleMain(ARG1=RDI, ARG2=RSI, CSSA=RDX, TCS=RCX)
    mov %rax, %rdx 
    mov %rbx, %rcx
    call __OE_HandleMain
    ud2

.forever:
    jmp .forever

.cfi_endproc

.size OE_Main, .-OE_Main