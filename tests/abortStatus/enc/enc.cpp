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
    __sync_fetch_and_add(args->thread_ready_count, 1);

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

    AbortStatusEncRecursionArg* args_host = (AbortStatusEncRecursionArg*)Args_;
    AbortStatusEncRecursionArg args = *args_host;

    // catch initial state: Tag, Input-structure.
    args.crc = Crc32::Hash(TAG_START_ENC, args);
    args_host->crc = args.crc;

    // recurse as needed, passing initial-state-crc as input
    if (args.recursions_left)
    {
        if (args.initial_count)
            args_host->initial_count = args.initial_count - 1;
        args_host->recursions_left = args.recursions_left - 1;
        result = oe_call_host("RecursionOcall", args_host);
    }
    else
    {
        // Notify control thread that this thread is ready.
        __sync_fetch_and_add(args_host->thread_ready_count, 1);

        // Wait for the is_enclave_crashed signal.
        while (*args_host->is_enclave_crashed == 0)
            ;

        // OCALL should return OE_ENCLAVE_ABORTING.
        if (oe_call_host("RecursionOcall", NULL) != OE_ENCLAVE_ABORTING)
        {
            args_host->crc = 0;
            return;
        }
    }

    // catch output state: Tag + result + modified host-struct, and original
    // input.
    args_host->crc = Crc32::Hash(TAG_END_ENC, result, *args_host, args);
}
