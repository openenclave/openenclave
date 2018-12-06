// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/atexit.h>
#include <openenclave/internal/print.h>
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

    if (!oe_is_outside_enclave(args, sizeof(AbortStatusArgs)))
    {
        return;
    }

    args->ret = 0;

    // Generate a hardware exception via an undefined instruction. Since there
    // is no handler to handle it, the enclave should abort itself.
    asm volatile("ud2" ::: "memory");
    // We should never get here...
    oe_host_printf("Error: unreachable code is reached. ");
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
    if (oe_call_host("foobar", NULL) == OE_ENCLAVE_ABORTING)
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

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    256,  /* HeapPageCount */
    64,   /* StackPageCount */
    5);   /* TCSCount */

OE_DEFINE_EMPTY_ECALL_TABLE();
