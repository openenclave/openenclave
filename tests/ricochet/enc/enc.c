// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef OE_BUILD_ENCLAVE
#define OE_BUILD_ENCLAVE
#endif
#include <openenclave/enclave.h>
#include <openenclave/bits/tests.h>
#include "../args.h"

OE_ECALL void Ricochet(void* args_)
{
    RicochetArgs* args = (RicochetArgs*)args_;

    OE_HostPrintf("Enclave Ricochet()\n");

    if (OE_CallHost("Ricochet", args) != OE_OK)
    {
        OE_TEST(0);
        return;
    }
}
