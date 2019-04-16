// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_PRINT_H
#define _OE_PRINT_H

#include <openenclave/corelibc/stdarg.h>
#include <openenclave/internal/defs.h>

OE_EXTERNC_BEGIN

int oe_host_vfprintf(int device, const char* fmt, oe_va_list ap_);

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

int oe_host_write(int device, const char* str, size_t len);

OE_EXTERNC_END

#endif /* _OE_PRINT_H */
