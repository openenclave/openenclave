// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>

OE_ECALL void Test(void* args_)
{
    int* args = (int*)args_;
    *args = 0;
}

OE_DEFINE_EMPTY_ECALL_TABLE();
