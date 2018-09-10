// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/hexdump.h>
#include "../args.h"

OE_ECALL void Test(void* args_)
{
    Args* args = (Args*)args_;

    oe_hex_dump(args->data, sizeof(args->data));

    const char* str = oe_hex_string(
        args->hexstr, sizeof(args->hexstr), args->data, sizeof(args->data));

    if (str != args->hexstr)
    {
        args->ret = -1;
        return;
    }

    args->ret = 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
