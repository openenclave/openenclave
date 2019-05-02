// Copyright (c) Microsoft Corporation. All rights reserved._ops
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_POSIX_CONSOLE_H
#define _OE_INTERNAL_POSIX_CONSOLE_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

/* Initialize the stdin, stdout, and stderr devices. */
int oe_initialize_console_devices(void);

OE_EXTERNC_END

#endif // _OE_INTERNAL_POSIX_CONSOLE_H
