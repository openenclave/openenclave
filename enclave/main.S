#include "asmdefs.h"
#include <openenclave/bits/context.inc>

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
    mov %rsp, %gs:TD_host_rsp
    mov %rbp, %gs:TD_host_rbp

.determine_entry_type:

    // Check whether this is a clean entry or a nested entry
    mov %gs:TD_depth, %r8 
    cmp $0, %r8 
    je .clean_entry

    // Check if this is exception dispatching request.
    cmp $0, %rax
    je .nested_entry

.exception_entry:
    // Get the first ssa address from tcs.
    mov %rbx, %r10
    add $OE_SSA_FROM_TCS_BYTE_OFFSET, %r10

    // Get the offset of current SSA from the begining of the SSA.
    dec %rax
    shl $0x0c, %rax

    // Get the address of current SSA.
    add %r10, %rax

    // Get the saved rsp. We can't depend on the TLS value to get the enclave rsp in exception entry since the value may 
    // not be set correctly.
    add $SGX_SSA_RSP_OFFSET, %r10
    mov (%r10), %rsp

    // align stack.
    and $-16, %rsp

    // Start the new stack under the red zone.
    sub $ABI_REDZONE_BYTE_SIZE, %rsp
    jmp .call_function

.nested_entry:

    // Restore stack pointer and enclave registers:
    mov %gs:TD_last_sp, %rsp

    // align the stack
    and $-16, %rsp 

    // Start the new stack under the red zone.
    sub $ABI_REDZONE_BYTE_SIZE, %rsp
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
    mov %gs:TD_host_rsp, %r8
    mov %gs:TD_host_rbp, %r9
    mov %r8, OM_HOST_RSP
    mov %r9, OM_HOST_RBP

    // Save the host return address to enclave stack.
    mov %gs:TD_host_rcx, %r8
    mov %r8, OM_HOST_RETURN_ADDR

    // Call __OE_HandleMain(ARG1=RDI, ARG2=RSI, CSSA=RDX, TCS=RCX, OUTPUTARG1=R8, OUTPUTARG2=R9)
    mov %rax, %rdx 
    mov %rbx, %rcx
    lea OM_HOST_OUTPUT_ARG1, %r8
    lea OM_HOST_OUTPUT_ARG2, %r9
    call __OE_HandleMain
    
    // Get the output parameters.
    mov OM_HOST_OUTPUT_ARG1, %rdi
    mov OM_HOST_OUTPUT_ARG2, %rsi

.determine_exit_type:

    // Check the depth of the ECALL stack (zero for clean exit)
    mov %gs:TD_depth, %r8
    cmp $0, %r8
    je .clean_exit

.nested_exit:

    // Construct the OE_OCallContext(rbp, return address).
    mov (4*OE_WORD_SIZE)(%rsp), %r12
    push %r12
    push %rbp
    mov %rsp, %r12

    // Save the parameters of _OE_Exit into stack.
    push %rdi
    push %rsi

    // Notify a nested exit happens.
    // _OE_NotifyNestedExistStart(rdi=arg1, rsi=ocallContext)
    mov %r12, %rsi
    call _OE_NotifyNestedExistStart

    // Restore the parameters of _OE_Exit from stack.
    pop %rsi
    pop %rdi

    // Restore the stack to correct status: rbp/rsp should not change after function call.
    pop %r12
    pop %r12

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

    mov OM_HOST_RETURN_ADDR, %rcx
    mov OM_HOST_RETURN_ADDR, %rbx
    mov OM_HOST_RSP, %rsp
    mov OM_HOST_RBP, %rbp
    
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
    //mov %rcx, %rbx
    mov $ENCLU_EEXIT, %rax
    ENCLU
    ud2

.forever:
    jmp .forever

.cfi_endproc

.size OE_Main, .-OE_Main

//==============================================================================
//
// void OE_ExceptionDispatcher(void)
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

.globl OE_ExceptionDispatcher
.type OE_ExceptionDispatcher, @function
OE_ExceptionDispatcher:
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
    call OE_SnapCurrentContext

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

    call _OE_ExceptionDispatcher

    // Should never reach here since _OE_ExceptionDispatcher will not return.

.foreverLoop:
    jmp .foreverLoop

    mov %rbp, %rsp
    pop %rdi
    pop %rbp
    pop %rsp
    retq
.cfi_endproc

.size OE_ExceptionDispatcher, .-OE_ExceptionDispatcher