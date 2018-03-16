// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/atexit.h>
#include <openenclave/enclave.h>
#include "../args.h"

bool TestCppException();

OE_ECALL void Test(void* args_)
{
    Args* args = (Args*)args_;
    args->ret = -1;

    if (!OE_IsOutsideEnclave(args, sizeof(Args)))
    {
        return;
    }

    if (!TestCppException())
    {
        args->ret = -1;
        OE_HostPrintf("Failed to test cpp exception.\n");
        return;
    }

    OE_HostPrintf("Cpp exception tests passed!\n");

    args->ret = 0;
    return;
}