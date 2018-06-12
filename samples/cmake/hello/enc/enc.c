// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>
#include <string.h>
#include "../args.h"

OE_ECALL void Hello(void* args_)
{
    Args* args = (Args*)args_;

    if (!oe_is_outside_enclave(args, sizeof(Args)))
    {
        args->ret = -1;
        return;
    }

    if (strcmp(args->in, "Hello World") != 0)
    {
        args->ret = -1;
        return;
    }

    if (oe_call_host("Hello", args) != OE_OK)
    {
        args->ret = -1;
        return;
    }

    oe_host_printf("enclave: hello!\n");

    args->ret = 0;
}
