// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

int oe_backtrace(void** buffer, int size)
{
    OE_UNUSED(size);

    *buffer = NULL;

    return 0;
}
