// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/bits/enclavelibc.h>
#include "../args.h"

OE_ECALL void Test(void* args_)
{
    Args* args = (Args*)args_;
    args->ret = 0;
}
