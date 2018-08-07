// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/atexit.h>
#include <openenclave/internal/print.h>
#include "../../ecall_ocall/crc32.h"
#include "../args.h"

// Explicitly call oe_abort to abort the enclave.
OE_ECALL void RegularAbort(void* args_)
{
    AbortStatusArgs* args = (AbortStatusArgs*)args_;

    if (!oe_is_outside_enclave(args, sizeof(AbortStatusArgs)))
    {
        return;
    }

    args->ret = 0;
    oe_abort();

    oe_host_printf("Error: unreachable code is reached.\n");
    args->ret = -1;
    return;
}

// When an un-handled hardware exception happens, enclave should abort itself.
OE_ECALL void GenerateUnhandledHardwareException(void* args_)
{
    AbortStatusArgs* args = (AbortStatusArgs*)args_;
    int t = 1;

    if (!oe_is_outside_enclave(args, sizeof(AbortStatusArgs)))
    {
        return;
    }

    args->ret = 0;

    // Generate a divide by zero hardware exception. Since there is no
    // handler to handle it, the enclave should abort itself.
    t = t / args->divisor;
    // We should never get here but this is to trick optimizer
    args->divisor = t;
    oe_host_printf(
        "Error: unreachable code is reached. Divisor=%d\n", args->divisor);
    args->ret = -1;
    return;
}

OE_ECALL void TestOCallAfterAbort(void* args_)
{
    AbortStatusArgs* args = (AbortStatusArgs*)args_;
    args->ret = -1;

    if (!oe_is_outside_enclave(args, sizeof(AbortStatusArgs)))
    {
        return;
    }

    // Notify control thread that this thread is ready.
    ++*args->thread_ready_count;

    // Wait for the is_enclave_crashed signal.
    while (*args->is_enclave_crashed == 0)
        ;

    // OCALL should return OE_ENCLAVE_ABORTING.
    if (oe_call_host("RecursionOcall", NULL) == OE_ENCLAVE_ABORTING)
    {
        args->ret = 0;
    }

    return;
}

OE_ECALL void NormalECall(void* args_)
{
    AbortStatusArgs* args = (AbortStatusArgs*)args_;
    args->ret = -1;

    if (!oe_is_outside_enclave(args, sizeof(AbortStatusArgs)))
    {
        return;
    }

    args->ret = 0;
    return;
}

OE_ECALL void EncRecursion(void* Args_)
{
    oe_result_t result = OE_OK;

    if (!oe_is_outside_enclave(Args_, sizeof(AbortStatusEncRecursionArg)))
        return;

    AbortStatusEncRecursionArg* argsHost = (AbortStatusEncRecursionArg*)Args_;
    AbortStatusEncRecursionArg args = *argsHost;

    // catch initial state: Tag, Input-structure.
    args.crc = Crc32::Hash(TAG_START_ENC, args);
    argsHost->crc = args.crc;

    // recurse as needed, passing initial-state-crc as input
    if (args.recursionsLeft)
    {
        if (args.initialCount)
            --argsHost->initialCount;        
        --argsHost->recursionsLeft;

        result = oe_call_host("RecursionOcall", argsHost);
    }
    else
    {
        // Notify control thread that this thread is ready.
        ++*argsHost->thread_ready_count;
       
        // Wait for the is_enclave_crashed signal.
        while (*argsHost->is_enclave_crashed == 0)
            ;

        // OCALL should return OE_ENCLAVE_ABORTING.
        if (oe_call_host("RecursionOcall", NULL) != OE_ENCLAVE_ABORTING)
        {
            argsHost->crc = 0;
            return;
        }
    }

    // catch output state: Tag + result + modified host-struct, and original
    // input.
    argsHost->crc = Crc32::Hash(TAG_END_ENC, result, *argsHost, args);
}
