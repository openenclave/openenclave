// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CORELIBC_STDIO_H
#define _OE_CORELIBC_STDIO_H

#include "bits/common.h"
#include "stdarg.h"

OE_CORELIBC_EXTERNC_BEGIN

typedef struct _IO_FILE FILE;

extern FILE* const stdin;
extern FILE* const stdout;
extern FILE* const stderr;

int oe_vsnprintf(char* str, size_t size, const char* format, oe_va_list ap);

OE_CORELIBC_PRINTF_FORMAT(3, 4)
int oe_snprintf(char* str, size_t size, const char* format, ...);

int oe_vprintf(const char* format, oe_va_list ap);

OE_CORELIBC_PRINTF_FORMAT(1, 2)
int oe_printf(const char* format, ...);

#if defined(OE_CORELIBC_NEED_STDC_NAMES)

OE_CORELIBC_INLINE
int vsnprintf(char* str, size_t size, const char* format, va_list ap)
{
    return oe_vsnprintf(str, size, format, ap);
}

OE_CORELIBC_PRINTF_FORMAT(3, 4)
OE_CORELIBC_INLINE
int snprintf(char* str, size_t size, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    return oe_vsnprintf(str, size, format, ap);
    va_end(ap);
}

OE_CORELIBC_INLINE
int vprintf(const char* format, va_list ap)
{
    return oe_vprintf(format, ap);
}

OE_CORELIBC_PRINTF_FORMAT(1, 2)
OE_CORELIBC_INLINE
int printf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    return oe_vprintf(format, ap);
    va_end(ap);
}

#endif /* defined(OE_CORELIBC_NEED_STDC_NAMES) */

OE_CORELIBC_EXTERNC_END

#endif /* _OE_CORELIBC_STDIO_H */
