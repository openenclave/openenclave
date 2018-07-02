// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include "../args.h"

OE_ECALL void test_enclave(void* args_)
{
    args_t* args = (args_t*)args_;

    args->ret = 0;
}
