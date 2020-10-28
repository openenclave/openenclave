// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "exception.h"
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <stdio.h>
#include "asmdefs.h"
#include "enclave.h"

/**
 * Relevant definitions from asmdefs.h copied locally
 * since asmdefs.h is too linux specific at the moment.
 */
#define ENCLU_ERESUME 3

oe_enclave_t* oe_query_enclave_instance(void* tcs);

/* Platform neutral exception handler */
uint64_t oe_host_handle_exception(oe_host_exception_context_t* context)
{
    uint64_t exit_code = context->rax;
    uint64_t tcs_address = context->rbx;
    uint64_t exit_address = context->rip;

    // Check if the signal happens inside the enclave.
    if ((exit_address == OE_AEP_ADDRESS) && (exit_code == ENCLU_ERESUME))
    {
        // Check if the enclave exception happens inside the first pass
        // exception handler.
        oe_thread_binding_t* thread_data = oe_get_thread_binding();
        if (thread_data->flags & _OE_THREAD_HANDLING_EXCEPTION)
        {
            abort();
        }

        // Call-in enclave to handle the exception.
        oe_enclave_t* enclave = oe_query_enclave_instance((void*)tcs_address);
        if (enclave == NULL)
        {
            abort();
        }

        // Set the flag marks this thread is handling an enclave exception.
        thread_data->flags |= _OE_THREAD_HANDLING_EXCEPTION;

        oe_exception_record_t oe_exception_record = {0};

        /* TODO PRP: We need to save the exception information in
         * oe_exception_record */

        // Call into enclave first pass exception handler.
        uint64_t arg_out = 0;
        uint64_t arg_in = (uint64_t)&oe_exception_record;

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
