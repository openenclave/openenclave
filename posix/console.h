// Copyright (c) Microsoft Corporation. All rights reserved._ops
// Licensed under the MIT License.

#ifndef _OE_POSIX_CONSOLE_H
#define _OE_POSIX_CONSOLE_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

oe_device_t* oe_get_stdin_device(void);

oe_device_t* oe_get_stdout_device(void);

oe_device_t* oe_get_stderr_device(void);

OE_EXTERNC_END

#endif // _OE_POSIX_CONSOLE_H
