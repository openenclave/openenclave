// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "exception.h"
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <stdio.h>
#include <windows.h>
#include "../enclave.h"
#include "../exception.h"

/**
 * The only thing that causes issues with simulation mode on Windows is the FS
 * register. The enclave uses FS register for thread-local storage, accessing
 * td_t, stack-protector etc. Simulation mode correctly sets up the FS register
 * prior to making an ecall (see host/sgx/enter.c).
 * Windows however restores the FS register to its original value, possibly
 * whenever the thread resumes execution. This causes crashes since the enclave
 * code expects FS to point to td_t whereas Windows thread scheduler has
 * reverted it. The FS values Windows uses point to invalid memory and thus
 * enclave code that uses FS register results in access violations.
 * The handler below restores FS to desired value when such a violation occurs.
 */
static LONG WINAPI _handle_simulation_mode_exception(
    struct _EXCEPTION_POINTERS* exception_pointers)
{
    PCONTEXT context = exception_pointers->ContextRecord;
    oe_thread_binding_t* binding = oe_get_thread_binding();

    // Check if the thread is bound to a simulation mode enclave.
    if (binding != NULL)
    {
        oe_enclave_t* enclave = binding->enclave;
        if (enclave->simulate)
        {
            // Determine if the exception happened within the enclave.
            uint64_t enclave_start = enclave->addr;
            uint64_t enclave_end = enclave->addr + enclave->size;
            if (context->Rip >= enclave_start && context->Rip < enclave_end)
            {
                // Check if the exception was due to an incorrect FS value.
                sgx_tcs_t* sgx_tcs = (sgx_tcs_t*)binding->tcs;
                uint64_t enclave_fsbase = enclave_start + sgx_tcs->fsbase;
                if (context->SegFs != enclave_fsbase)
                {
                    // Update the FS register and continue execution.
                    oe_set_fs_register_base(enclave_fsbase);
                    return OE_EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/**
 * The Windows structured exception handler modeled.
 */
static LONG WINAPI
_host_exception_handler(struct _EXCEPTION_POINTERS* exception_pointers)
{
    PCONTEXT context = exception_pointers->ContextRecord;
    oe_host_exception_context_t host_context = {0};
    host_context.rax = (uint64_t)context->Rax;
    host_context.rbx = (uint64_t)context->Rbx;
    host_context.rip = (uint64_t)context->Rip;

    // Call platform neutral handler.
    uint64_t action = oe_host_handle_exception(&host_context);

    if (action == OE_EXCEPTION_CONTINUE_EXECUTION)
    {
        // Exception has been handled.
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else
    {
        // Exception has not been handled.
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

#define SET_AS_FIRST_HANDLER 1

void oe_initialize_host_exception()
{
    AddVectoredExceptionHandler(SET_AS_FIRST_HANDLER, _host_exception_handler);
}

static void _register_simulation_mode_handler(void)
{
    AddVectoredExceptionHandler(
        SET_AS_FIRST_HANDLER, _handle_simulation_mode_exception);
}

void oe_prepend_simulation_mode_exception_handler()
{
    static oe_once_type _once;
    oe_once(&_once, _register_simulation_mode_handler);
}
