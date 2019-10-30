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
    while (true)
    {
        asm volatile("pushfq \n\t"         // Save flags
                     "sub $8, %%rsp  \n\t" // Save mxcsr
                     "stmxcsr (%%rsp) \n\t"
                     "sub $512, %%rsp \n\t" // Save floating-point state
                     "fxsave (%%rsp) \n\t"

                     "mov %0, %%rdi \n\t"        // Move arg1 to rdi
                     "mov %1, %%rsi \n\t"        // Move arg2 to rsi
                     "lea 1f(%%rip), %%rcx \n\t" // Move return address to rcx
                     "mov 72(%%rbx), %%rdx \n\t" // Load enclave entry-point
                     "jmp *%%rdx \n\t"           // Call into the enclave
                     "1: \n\t"            /// Local label for return address
                     "mov %%rdi, %0 \n\t" // Update arg1
                     "mov %%rsi, %1 \n\t" // Update arg2

                     "fxrstor (%%rsp) \n\t" // Restore floating-point state
                     "add $512, %%rsp \n\t"
                     "ldmxcsr (%%rsp) \n\t" // Restore mxcsr
                     "add $8, %%rsp \n\t"
                     "popfq \n\t" // Restore flags

                     // arg1, arg2 are in-out. Passed in r14 and r15
                     : "+r"(arg1), "+r"(arg2)

                     // Pass CSSA (0), tcs and aep in rax, rbx and rcx
                     // as required by enclu instruction
                     : "a"(0), "b"(tcs), "c"(aep)

                     // Ask the compiler to save all general-purpose registers
                     // except r14 and r15 which are used to pass arg1 and arg2
                     : "rdi",
                       "rsi",
                       "rdx",
                       "rbp",
                       "r8",
                       "r9",
                       "r10",
                       "r11",
                       "r12",
                       "r13");

        const oe_code_t code = oe_get_code_from_call_arg1(arg1);
        if (code == OE_CODE_OCALL)
        {
            __oe_host_stack_bridge(tcs, aep, arg1, arg2, &arg1, &arg2, enclave);
        }
        else
        {
            break;
        }
    }

    *arg3 = arg1;
    *arg4 = arg2;
}
