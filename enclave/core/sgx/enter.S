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
//         (1) Calculates the enclave stack base
//         (2) Sets up the enclave stack frame
//         (3) Calls call_function which in turn calls __oe_handle_main
//
//==============================================================================

.globl oe_enter
.type oe_enter, @function
oe_enter:
.cfi_startproc

    // Prepare arguments for call_function
    mov %rax, %rdx
    mov %rsp, %r8
    mov %rbp, %r9

    mov %rdi, %rax
    shr $48, %rax
.code_ecall:
    cmp $CODE_ECALL, %rax
    jne .code_oret
    mov %rdi, %rax
    shr $32, %rax
    cmp $FUNC_VIRTUAL_EXCEPTION_HANDLER, %ax
    je .code_ecall_virtual_exception
    mov $TD_STATUS_NONE, %rax
    mov $TD_STATUS_IN_ECALL, %r10
    jmp .validate_call

.code_ecall_virtual_exception:
    mov $TD_STATUS_IN_ECALL, %rax
    mov $TD_STATUS_HANDLING_EXCEPTION, %r10
    jmp .validate_call

.code_oret:
    cmp $CODE_ORET, %rax
    jne .invalid_call
    mov $TD_STATUS_AWAITING_ORET, %rax
    mov $TD_STATUS_IN_ECALL, %r10

.validate_call:
    lfence
    lock cmpxchg %r10, %gs:td_status
    jnz .invalid_call

    // Set rsp to below the stack guard page (tcs - OE_PAGE_SIZE).
    // This is the starting value of rsp for an ECALL.
    lea -OE_PAGE_SIZE(%rbx), %rsp
    sub $ABI_REDZONE_BYTE_SIZE, %rsp

	// If an OCALL has been made, td_last_sp would have been non-zero.
    // If availble, td_last_sp must be used resume the stack where it was left off.
    mov %gs:td_last_sp, %r10
    cmp $0, %r10
    cmovne %r10, %rsp

    // If this is an exception handling-request, cssa/rax will be non-zero. Just as in case of an ocall return, the stack must resume at the location when control exited the enclave. However, for exception code path, td_last_sp is not set. Instead, the correct value of rsp must be fetched from the SSA.

    // Get the first ssa address from tcs.
    lea OE_SSA_FROM_TCS_BYTE_OFFSET(%rbx), %r10

    // Get the offset of current SSA from the begining of the SSA.
    dec %rax
    shl $0x0c, %rax

    // Get the address of current SSA.
    add %r10, %rax

    cmp $0, %rdx
    cmovne %rax, %rdx
    cmovne SGX_SSA_RSP_OFFSET(%r10), %rsp

    // Now rsp has been setup to handle ecall, ocall-return as well as exception
    // Align stack and allocate ABI redzone
    and $-16, %rsp
    sub $ABI_REDZONE_BYTE_SIZE, %rsp

    // Now that rsp has been setup correctly, perform ABI required
    // initialization.
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

    // Make the call into call_function
    // Note rbp still contains the host rbp and thus calling call_function would
    // automatically stitch the ecall stack back to the host.
    // 	void call_function(
    // 	      uint64_t arg1,          /* rdi */
    // 	      uint64_t arg2,          /* rsi */
    //	      uint64_t cssa,          /* rdx */
    //        uint64_t host_ret_addr, /* rcx */
    //        uint64_t host_rsp,      /* r8 */
    //        uint64_t host_rbp,      /* r9 */
    //        void* tcs)              /* on stack */
    push $0   // For 16-byte alignment upon entry to call_function
    push %rbx // tcs
    push %rcx  // Push the host return address and jump (equivalent to a call)
    jmp call_function

.invalid_call:
    mov %rcx, %rbx
    mov  $4, %rax
    cmpq $0, %gs:td_simulate
    jne .eexit_sim
    enclu
.eexit_sim:
    mov $1, %rax
    jmp *%rcx

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
