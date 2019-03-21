// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/thread.h>

static void (*_oe_exit_handler)(int status);

void oe_set_exit_handler(void (*handler)(int status))
{
    _oe_exit_handler = handler;
}

OE_NO_RETURN void oe_exit(int status)
{
    if (_oe_exit_handler)
    {
        (*_oe_exit_handler)(status);
    }
    else
    {
        oe_printf("oe_exit() panic");
        oe_abort();
    }

    /* Never return. */
    for (;;)
        ;
}
