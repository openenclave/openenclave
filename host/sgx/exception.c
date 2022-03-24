// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "exception.h"
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include "asmdefs.h"
#include "enclave.h"

/**
 * Relevant definitions from asmdefs.h copied locally
 * since asmdefs.h is too linux specific at the moment.
 */
#define ENCLU_ERESUME 3

oe_enclave_t* oe_query_enclave_instance(void* tcs);

/* The host will forward the #PF information to the enclave when
 * this variable is set. The enclave runs on SGX1 CPUs will simulate
 * #PF based on the forwarded information only in debug mode.
 * By default, the variable is set only when CapturePFGPExceptions=1
 * on SGX1 CPUs. */
static volatile int _debug_pf_simulation;

#define LINUX_SIGSEGV 11

void oe_sgx_host_enable_debug_pf_simulation(void);

void oe_sgx_host_enable_debug_pf_simulation(void)
{
    _debug_pf_simulation = 1;
}

/* Platform neutral exception handler */
uint64_t oe_host_handle_exception(oe_host_exception_context_t* context)
{
    uint64_t exit_code = context->rax;
    uint64_t tcs_address = context->rbx;
    uint64_t exit_address = context->rip;
    uint64_t signal_number = context->signal_number;
    uint64_t faulting_address = context->faulting_address;

    // Check if the signal happens inside the enclave.
    if ((exit_address == OE_AEP_ADDRESS) && (exit_code == ENCLU_ERESUME))
    {
        // Check if the enclave exception happens inside the first pass
        // exception handler.
        oe_thread_binding_t* thread_data = oe_get_thread_binding();
        if (thread_data->flags & _OE_THREAD_HANDLING_EXCEPTION)
        {
            // Return directly.
            return OE_EXCEPTION_CONTINUE_EXECUTION;
        }

        // Call-in enclave to handle the exception.
        oe_enclave_t* enclave = oe_query_enclave_instance((void*)tcs_address);
        if (enclave == NULL)
        {
            abort();
        }

        // Set the flag marks this thread is handling an enclave exception.
        thread_data->flags |= _OE_THREAD_HANDLING_EXCEPTION;

        // Pass the faulting address to allow the enclave to simulate
        // #PF in debug mode
        oe_exception_record_t oe_exception_record = {0};
        oe_exception_record.faulting_address = faulting_address;

        // Call into enclave first pass exception handler.
        uint64_t arg_out = 0;
        uint64_t arg_in = 0;

        /* Only pass the oe_exception_record if the signal number is SIGSEGV
         * (Linux definition) for #PF simulation. If the signal_number is
         * neither zero nor SIGSEGV, pass the number for in-enclave thread
         * interrupt support. For the rest of cases, pass zero value. */
        if (signal_number == LINUX_SIGSEGV && _debug_pf_simulation)
            arg_in = (uint64_t)&oe_exception_record;
        else if (signal_number != 0 && signal_number != LINUX_SIGSEGV)
            arg_in = signal_number;

        oe_result_t result = oe_ecall(
            enclave, OE_ECALL_VIRTUAL_EXCEPTION_HANDLER, arg_in, &arg_out);

        // Reset the flag
        thread_data->flags &= (~_OE_THREAD_HANDLING_EXCEPTION);
        if (result == OE_OK && arg_out == OE_EXCEPTION_CONTINUE_EXECUTION)
        {
            // This exception has been handled by the enclave. Let's resume.
            return OE_EXCEPTION_CONTINUE_EXECUTION;
        }
        else
        {
            // Un-handled enclave exception happened.
            // Explicitly call out if the enclave is in the aborting status
            if (arg_out == OE_ENCLAVE_ABORTING)
                OE_TRACE_ERROR(
                    "Invalid exception occurred. The enclave is aborting.");

            // We continue the exception handler search as if it were a
            // non-enclave exception.
            return OE_EXCEPTION_CONTINUE_SEARCH;
        }
    }
    else
    {
        // Not an exclave exception.
        // Continue searching for other handlers.
        return OE_EXCEPTION_CONTINUE_SEARCH;
    }
}
