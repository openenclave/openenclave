// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/print.h>
#include "internal_t.h"

int oe_internal_ping_ecall(int value)
{
    int retval = -1;

    if (oe_internal_ping_ocall(&retval, value) != OE_OK)
        return -1;

    return retval;
}
