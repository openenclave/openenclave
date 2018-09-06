// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/atexit.h>
#include <openenclave/internal/print.h>
#include "../args.h"

bool TestCppException();

OE_ECALL void Test(void* args_)
{
    Args* args = (Args*)args_;
    if (!oe_is_outside_enclave(args, sizeof(Args)))
    {
        return;
    }

    args->ret = -1;
    if (!TestCppException())
    {
        args->ret = -1;
        oe_host_printf("Failed to test cpp exception.\n");
        return;
    }

    oe_host_printf("Cpp exception tests passed!\n");

    args->ret = 0;
    return;
}

bool ExceptionInUnwind();
bool ExceptionSpecification();
bool UnhandledException();
OE_ECALL void TestUnhandledException(void* args_)
{
    Args* args = (Args*)args_;
    if (!oe_is_outside_enclave(args, sizeof(Args)))
    {
        return;
    }

    args->ret = -1;
    oe_host_printf("This test will crash the enclave.\n");
    args->ret = 0;
    switch (args->func_num)
    {
        case EXCEPTION_SPECIFICATION:
            ExceptionSpecification();
            break;

        case EXCEPTION_IN_UNWIND:
            ExceptionInUnwind();
            break;

        case UNHANDLED_EXCEPTION:
            UnhandledException();
            break;

        default:
            break;
    }

    oe_host_printf("Error: unreachable code is reached.\n");
    args->ret = -1;
    return;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
