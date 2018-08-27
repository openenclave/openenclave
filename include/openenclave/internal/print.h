// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_PRINT_H
#define _OE_PRINT_H

#include <openenclave/internal/defs.h>
#include <openenclave/internal/types.h>

OE_EXTERNC_BEGIN

int __oe_host_puts(const char* str);

int __oe_host_print(int device, const char* str, size_t len);

int __oe_host_vfprintf(int device, const char* fmt, oe_va_list ap_);

int __oe_host_putchar(int c);

/**
 * Print formatted characters to the host's console.
 *
 * This function writes formatted characters to the host console. It is based
 * on oe_vsnprintf(), which has limited support for format types.
 *
 * @param fmt The limited printf style format.
 *
 * @returns The number of characters that were written.
 *
 */
OE_PRINTF_FORMAT(1, 2)
int oe_host_printf(const char* fmt, ...);

/**
 * Print formatted characters to the host's stdout or stderr.
 *
 * This function writes formatted characters to the host's stdout or stderr. It
 * is based on oe_vsnprintf(), which has limited support for format types.
 *
 * @param fmt The limited printf style format.
 * @param device 0 for stdout and 1 for stderr
 * @returns The number of characters that were written.
 *
 */
OE_PRINTF_FORMAT(2, 3)
int oe_host_fprintf(int device, const char* fmt, ...);

OE_EXTERNC_END

#ifndef OE_BUILD_ENCLAVE
#error "this is an enclave header only"
#endif

#endif /* _OE_PRINT_H */
