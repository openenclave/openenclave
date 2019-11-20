// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/calls.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/types.h>
#include "asmdefs.h"

void oe_cleanup_xstates(void);

//==============================================================================
// void _oe_exit_enclave(uint64_t arg1,     /* RDI */
//                       uint64_t arg2,     /* RSI */
//                       uint64_t host_rip, /* RDX */
//                       uint64_t host_rsp, /* RCX */
//                       uint64_t host_rbp) /* R8 */
//
// Purpose:
//     Restores user registers and executes the EEXIT instruction to leave the
//     enclave and return control to the host. This function is called for two
//     reasons:
//
//         (1) To perform an ERET (ECALL return)
//         (2) To perform an OCALL
//         (3) To perform an abort
//
// Tasks:
//
//      (1) Determines whether the caller is performing an ocall or an ecall
//          exit. If this is an ocall, then td.last_sp is set to the current
//          rsp value so that when the ocall returns, it resumes at the correct
//          stack location. Note this rsp value does not need to be precise.
//          It just needs to be any value within this functions frame.
//          Ocall return uses longjmp to resume execution.
//
//      (2) Execute the SGX EEXIT instruction for hardware-mode; for simulation
//          mode, return control to the host via a jmp instruction.
//
//      (3) When doing an abort, set the td_depth to zero to indicate that
//          the current ecall has completed.
//
// Compilation:
//      This function must be compiled with -fno-omit-frame-pointer so that
//      rbp is used as System V x64 ABI frame-pointer.
//==============================================================================
OE_NO_RETURN
OE_NEVER_INLINE
void _oe_exit_enclave(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t host_rip,
    uint64_t host_rsp,
    uint64_t host_rbp)
{
    oe_code_t code = oe_get_code_from_call_arg1(arg1);
    oe_result_t result = oe_get_result_from_call_arg1(arg1);
    oe_ocall_context_t* context = NULL;
    td_t* td = oe_get_td();

    if (code == OE_CODE_OCALL)
    {
        // Set the last_sp value to any value within this frame.
        // When ocall returns, it will set RSP to last_sp -  ABI_RED_ZONE and
        // resume execution.
        td->base.last_sp = (uint64_t)(void*)&td;

        // Fetch the frame pointer of this function which gives the
        // rbp, return-address of the caller. Pass it along to
        // oe_notify_nested_exit_start which will install these values into
        // the callsite information. The debugger will read these values
        // and stitch the ocall stack back to this function's caller.
        asm volatile("mov %%rbp, %0" : "=r"(context));
        oe_notify_nested_exit_start(arg1, context);
    }
    else if (code == OE_CODE_ERET)
    {
        if (result != OE_REENTRANT_ECALL)
        {
            // Clear out the last_sp.
            td->base.last_sp = 0;
        }
        else
        {
            // The rentrant call should not clear out the last_sp value that
            // any active OCALL may need.
        }

        // An abort is a short-circuited ecall-exit.
        // depth must be reset.
        // Note: It would be good to clear td correctly for abort.
        if (arg2 == OE_ENCLAVE_ABORTING)
            td->depth = 0;
    }

    // Cleanup extended processor states.
    oe_cleanup_xstates();

    // ENCLU_(EEXIT) must set RDI and RSI to arg1 and arg2.
    register uint64_t rdi __asm__("rdi") = arg1;
    register uint64_t rsi __asm__("rsi") = arg2;

    // RBX must contain the host return address.
    register uint64_t rbx __asm__("rbx") = host_rip;

    // RAX must contin the leaf ENCLU_EEXIT.
    // For simulation mode, RAX must be 1.
    register uint64_t rax __asm__("rax") = td->simulate ? 1 : ENCLU_EEXIT;

    // RSP and RBP must be restored to host values. The values are passed in
    // to the assembly snippet in RCX and RDX.
    register uint64_t rcx __asm__("rcx") = host_rsp;
    register uint64_t rdx __asm__("rdx") = host_rbp;

    asm volatile(
        // Clear general purpose registers.
        "xor %%r8, %%r8 \n\t"
        "xor %%r9, %%r9 \n\t"
        "xor %%r10, %%r10 \n\t"
        "xor %%r11, %%r11 \n\t"
        "xor %%r12, %%r12 \n\t"
        "xor %%r13, %%r13 \n\t"
        "xor %%r14, %%r14 \n\t"
        "xor %%r15, %%r15 \n\t"

        // Clear flags.
        "push %%r15 \n\t"
        "popf \n\t"

        // Restore host RSP and RBP.
        "mov %%rcx, %%rsp \n\t"
        "mov %%rdx, %%rbp \n\t"
        "xor %%rcx, %%rcx \n\t"
        "xor %%rdx, %%rdx \n\t"

        // Execute either ENCLU or jmp based on RAX value
        // which will be 1 for simulation mode. See above.
        "cmp $1, %%rax \n\t"
        "je 2f \n\t"
        "1: enclu \n\t"
        "2: jmp *%%rbx \n\t"
        "ud2 \n\t"
        :
        : "r"(rdi), "r"(rsi), "r"(rax), "r"(rbx), "r"(rcx), "r"(rdx));

    // This function does not return.
    while (1)
        ;
}

//==============================================================================
//
// This function is wrapper of _oe_exit_enclave. It is needed to stitch the host
// stack and enclave stack together.
//
// oe_exit_enclave is #defined to __morestack.
//
// N.B: Don't change the function name, otherwise debugger can't work. GDB
// depends on this hardcode function name when does stack walking for split
// stack.
//==============================================================================
void oe_exit_enclave(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t host_rip,
    uint64_t host_rsp,
    uint64_t host_rbp)
{
    _oe_exit_enclave(arg1, arg2, host_rip, host_rsp, host_rbp);
}
