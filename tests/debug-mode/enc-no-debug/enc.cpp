// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>

OE_ECALL void Test(void* args_)
{
   bool* debug = (bool*)args_;

    if (!debug)
        return;

    OE_TEST(!*debug);
}
