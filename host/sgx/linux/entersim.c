// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/calls.h>
#include <openenclave/internal/context.h>
#include <openenclave/internal/sgxtypes.h>
#include "../asmdefs.h"

void oe_enter_sim(
    void* tcs,
    uint64_t aep,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4,
    oe_enclave_t* enclave)
{
    oe_enclu_context_t context;
    context.tcs = tcs;
    context.aep = aep;
    context.arg1 = arg1;
    context.arg2 = arg2;

    while (true)
    {
        asm volatile("fxsave (%0) \n\t"     // Save floating-point state
                     "stmxcsr 512(%0) \n\t" // Save mxcsr
                     "push %%rbp \n\t"      // Save rbp
                     "pushfq \n\t"          // Save flags
                     "push %0 \n\t"         // Save r8

                     "mov $0, %%rax \n\t"        // CSSA
                     "mov 520(%0), %%rbx \n\t"   // tcs
                     "lea 1f(%%rip), %%rcx \n\t" // return address
                     "mov 536(%0), %%rdi \n\t"   // arg1
                     "mov 544(%0), %%rsi \n\t"   // arg2

                     "mov 72(%%rbx), %%rdx \n\t" // enclave entry-point
                     "jmp *%%rdx \n\t"

                     "1: \n\t"        // return address
                     "pop %0 \n\t"    // Restore r8
                     "popfq \n\t"     // Restore flags
                     "pop %%rbp \n\t" // Restore rbp

                     "mov %%rdi, 536(%0) \n\t" // Update arg1
                     "mov %%rsi, 544(%0) \n\t" // Update arg2

                     "ldmxcsr 512(%0) \n\t" // Restore mxcsr
                     "fxrstor (%0) \n\t"    // Restore floating-point state
                     :
                     : "r"(&context) // Use either r8 or rbp to pass context
                     : "rax",        // Mark all other registers as clobbered
                       "rbx", // Alternatively we could explicitly save and
                       "rcx", // restore these registers in the asm block.
                       "rdx",
                       "rdi",
                       "rsi",
                       "r9",
                       "r10",
                       "r11",
                       "r12",
                       "r13",
                       "r14",
                       "r15",
                       "memory");

        const oe_code_t code = oe_get_code_from_call_arg1(context.arg1);
        if (code == OE_CODE_OCALL)
        {
            __oe_dispatch_ocall(
                context.arg1,
                context.arg2,
                &context.arg1,
                &context.arg2,
                tcs,
                enclave);
        }
        else
        {
            break;
        }
    }

    *arg3 = context.arg1;
    *arg4 = context.arg2;
}
