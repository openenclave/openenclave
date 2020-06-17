// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_WINDOWS_EXCEPTION_H
#define _OE_HOST_WINDOWS_EXCEPTION_H

#include <openenclave/bits/types.h>
#include <openenclave/internal/calls.h>

/* Add simulation mode exception handler as the first handler. */
void oe_prepend_simulation_mode_exception_handler(void);

#endif // _OE_HOST_WINDOWS_EXCEPTION_H
