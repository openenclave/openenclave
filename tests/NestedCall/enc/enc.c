#include <openenclave/enclave.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/jump.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/fault.h>
#include <openenclave/bits/calls.h>
#include <openenclave/bits/reloc.h>
#include <openenclave/bits/globals.h>
#include <openenclave/bits/atexit.h>
#include <openenclave/bits/trace.h>
#include "../args.h"

volatile int s = 0;

// This function will generate the divide by zero function. 
// The handler will catch this exception and fix it, and continue execute.
int DivideByZeroExceptionFunction(void)
{
    int ret = 1;
    ret = ret / s;
    return ret;
}

uint64_t TestDivideByZeroHandler(OE_EXCEPTION_RECORD *exception_record)
{
    if (exception_record->code != EXCEPTION_DIVIDE_BY_ZERO)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Skip the idiv instruction.
    exception_record->context->rip += 2;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static OE_OnceType _enclave_exception_once;

static void _InitializeExceptionImp(void)
{
    if (OE_AddVectoredExceptionHandler(0, TestDivideByZeroHandler) == NULL)
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
        OE_HostPrintf("Enclave: EnclaveNestCalls depth [%d] returned!\n", curDepth);
        args->ret = 0;
        return;
    }

    args->depth--;

    // Generate a exception in nested call in.
    if (args->testEh > 0)
    {
        DivideByZeroExceptionFunction();
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
