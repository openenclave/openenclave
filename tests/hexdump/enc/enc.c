// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/hexdump.h>
#include "../args.h"

OE_ECALL void Test(void* args_)
{
    Args* args = (Args*)args_;

    OE_HexDump(args->data, sizeof(args->data));

    const char* str = OE_HexString(
        args->hexstr, sizeof(args->hexstr), args->data, sizeof(args->data));

    if (str != args->hexstr)
    {
        args->ret = -1;
        return;
    }

    args->ret = 0;
}
