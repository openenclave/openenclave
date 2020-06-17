// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ERROR_H
#define _OE_ERROR_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <stdio.h>

OE_EXTERNC_BEGIN

OE_PRINTF_FORMAT(3, 4)
void __oe_put_err(const char* file, unsigned int line, const char* format, ...);

void oe_set_program_name(const char* name);

#define oe_put_err(...) __oe_put_err(__FILE__, __LINE__, __VA_ARGS__)

OE_EXTERNC_END

#endif /* _OE_ERROR_H */
