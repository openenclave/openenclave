// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>

OE_ECALL void Test(void* args)
{
    int* ret = (int*)args;

    if (!ret)
        return;

    *ret = 0;
}
