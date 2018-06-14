// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include "../args.h"

OE_ECALL void Ricochet(void* args_)
{
    RicochetArgs* args = (RicochetArgs*)args_;

    oe_host_printf("Enclave Ricochet()\n");

    if (oe_call_host("Ricochet", args) != OE_OK)
    {
        OE_TEST(0);
        return;
    }
}
