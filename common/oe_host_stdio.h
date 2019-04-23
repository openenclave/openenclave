// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_STDIO_H
#define _OE_HOST_STDIO_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/stdarg.h>

OE_EXTERNC_BEGIN

#if 0

typedef struct FILE OE_FILE;
#define oe_in stdin
#define oe_out stdout
#define oe_err stderr

OE_INLINE
int oe_vsnprintf(char* str, size_t size, const char* format, va_list ap)
{
    return vsnprintf(str, size, format, ap);
}

OE_PRINTF_FORMAT(3, 4)
OE_INLINE
int oe_snprintf(char* str, size_t size, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    return vsnprintf(str, size, format, ap);
    va_end(ap);
}

OE_INLINE
int oe_vprintf(const char* format, va_list ap)
{
    return vprintf(format, ap);
}

OE_PRINTF_FORMAT(1, 2)
OE_INLINE
int oe_printf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    return vprintf(format, ap);
    va_end(ap);
}

#endif

OE_EXTERNC_END

#endif /* _OE_HOST_STDIO_H */
