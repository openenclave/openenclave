// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <stdio.h>
#include <string.h>
#include "../args.h"

OE_ECALL void Enclave_HelloWorld(void* _args)
{
    Args* args = (Args*)_args;
    oe_host_printf("Enclave: Hello World!\n");
    args->ret = 0;
}

