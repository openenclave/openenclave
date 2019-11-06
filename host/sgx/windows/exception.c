// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../exception.h"
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <stdio.h>
#include <windows.h>
#include "../enclave.h"

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
