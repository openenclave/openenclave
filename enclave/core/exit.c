// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/defs.h>

OE_NO_RETURN void oe_exit(int status)
{
    OE_UNUSED(status);

    oe_printf("oe_exit() panic");
    oe_abort();

    /* Never return. */
    for (;;)
        ;
}
