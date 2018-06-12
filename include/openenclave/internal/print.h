// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_PRINT_H
#define _OE_PRINT_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

int __oe_host_puts(const char* str);

int __oe_host_print(int device, const char* str, size_t len);

int __oe_host_vfprintf(int device, const char* fmt, oe_va_list ap_);

int __oe_host_putchar(int c);

OE_EXTERNC_END

#endif /* _OE_PRINT_H */
