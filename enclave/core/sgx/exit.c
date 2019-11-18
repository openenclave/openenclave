// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/calls.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/types.h>
#include "asmdefs.h"

void oe_cleanup_xstates(void);

__attribute__((noreturn)) OE_NEVER_INLINE void _oe_exit_enclave(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t host_rip,
    uint64_t host_rsp,
    uint64_t host_rbp)
{
    oe_code_t code = oe_get_code_from_call_arg1(arg1);
    oe_ocall_context_t* context = NULL;
    td_t* td = oe_get_td();

    if (code == OE_CODE_OCALL)
    {
        td->base.last_sp = (uint64_t)(void*)&td;
        td->status = TD_STATUS_AWAITING_ORET;
        asm volatile("mov %%rbp, %0" : "=r"(context));
        oe_notify_nested_exit_start(arg1, context);
    }
    else if (code == OE_CODE_ERET)
    {
        td->base.last_sp = 0;

        if (td->status == TD_STATUS_HANDLING_EXCEPTION)
            td->status = TD_STATUS_IN_ECALL;
        else if (td->status == TD_STATUS_IN_ECALL)
            td->status = TD_STATUS_NONE;

        if (arg2 == OE_ENCLAVE_ABORTING)
            td->depth = 0;
    }

    oe_cleanup_xstates();

    register uint64_t rax __asm__("rax") = td->simulate ? 1 : 4;
    register uint64_t rbx __asm__("rbx") = host_rip;
    register uint64_t rcx __asm__("rcx") = host_rsp;
    register uint64_t rdx __asm__("rdx") = host_rbp;
    register uint64_t rdi __asm__("rdi") = arg1;
    register uint64_t rsi __asm__("rsi") = arg2;

    asm volatile("xor %%r8, %%r8 \n\t"
                 "xor %%r9, %%r9 \n\t"
                 "xor %%r10, %%r10 \n\t"
                 "xor %%r11, %%r11 \n\t"
                 "xor %%r12, %%r12 \n\t"
                 "xor %%r13, %%r13 \n\t"
                 "xor %%r14, %%r14 \n\t"
                 "xor %%r15, %%r15 \n\t"

                 "push %%r15 \n\t"
                 "popf \n\t"

                 "mov %%rcx, %%rsp \n\t"
                 "mov %%rdx, %%rbp \n\t"
                 "xor %%rcx, %%rcx \n\t"
                 "xor %%rdx, %%rdx \n\t"

                 "cmp $1, %%rax \n\t"
                 "je 2f \n\t"
                 "1: enclu \n\t"
                 "2: jmp *%%rbx \n\t"
                 :
                 : "r"(rdi), "r"(rsi), "r"(rax), "r"(rbx), "r"(rcx), "r"(rdx));

    while (1)
        ;
}

__attribute__((noreturn)) void oe_exit_enclave(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t host_rip,
    uint64_t host_rsp,
    uint64_t host_rbp)
{
    _oe_exit_enclave(arg1, arg2, host_rip, host_rsp, host_rbp);
}
