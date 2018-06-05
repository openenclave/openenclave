// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include "../args.h"

// This function will generate the divide by zero function.
// The handler will catch this exception and fix it, and continue execute.
// It will return 0 if success.
int DivideByZeroExceptionFunction(void)
{
    int ret = 1;
    int s = 0;
    float f = 0;
    double d = 0;

    f = 0.31;
    d = 0.32;

    ret = ret / s;

    // Check if the float registers are recovered correctly after the exception
    // is handled.
    if (f < 0.309 || f > 0.321 || d < 0.319 || d > 0.321)
    {
        return ret;
    }

    return 0;
}

uint64_t TestDivideByZeroHandler(OE_ExceptionRecord* exception_record)
{
    if (exception_record->code != OE_EXCEPTION_DIVIDE_BY_ZERO)
    {
        return OE_EXCEPTION_CONTINUE_SEARCH;
    }

    // Skip the idiv instruction.
    exception_record->context->rip += 3;
    return OE_EXCEPTION_CONTINUE_EXECUTION;
}

static OE_OnceType _enclave_exception_once;

static void _InitializeExceptionImp(void)
{
    if (OE_AddVectoredExceptionHandler(false, TestDivideByZeroHandler) == NULL)
    {
        OE_Abort();
    }

    return;
}

void _RegisterExceptionHandler()
{
    OE_Once(&_enclave_exception_once, _InitializeExceptionImp);
}

OE_ECALL void EnclaveNestCalls(void* args_)
{
    Args* args = (Args*)args_;
    char str[128];
    int curDepth = args->depth;
    OE_Snprintf(str, sizeof(str), "Nested call depth [%d].", curDepth);

    // Register exception handler.
    _RegisterExceptionHandler();

    if (!OE_IsOutsideEnclave(args, sizeof(Args)))
    {
        args->ret = -1;
        return;
    }

    OE_HostPrintf("Enclave: EnclaveNestCalls depth [%d] started!\n", curDepth);

    if (args->depth <= 0)
    {
        OE_HostPrintf(
            "Enclave: EnclaveNestCalls depth [%d] returned!\n", curDepth);
        args->ret = 0;
        return;
    }

    args->depth--;

    // Generate a exception in nested call in.
    if (args->testEh > 0)
    {
        if (DivideByZeroExceptionFunction() != 0)
        {
            args->ret = -1;
            return;
        }
    }

    if (OE_Strcmp(args->in, str) != 0)
    {
        args->ret = -1;
        return;
    }

    // Call out to host which will call in again.
    if (OE_CallHost("HostNestCalls", args) != OE_OK)
    {
        args->ret = -1;
        return;
    }

    // Check if it get the correct output parameter.
    if (OE_Strcmp(args->out, str) != 0)
    {
        args->ret = -1;
        return;
    }

    OE_HostPrintf("Enclave: EnclaveNestCalls depth [%d] returned!\n", curDepth);

    args->ret = 0;
    return;
}
