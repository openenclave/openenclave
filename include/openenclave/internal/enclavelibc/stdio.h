// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVELIBC_STDIO_H
#define _OE_ENCLAVELIBC_STDIO_H

#include "bits/common.h"
#include "stdarg.h"

OE_ENCLAVELIBC_EXTERNC_BEGIN

typedef struct _OE_IO_FILE OE_FILE;
extern OE_FILE* const oe_stdin;
extern OE_FILE* const oe_stdout;
extern OE_FILE* const oe_stderr;

int oe_vsnprintf(char* str, size_t size, const char* format, oe_va_list ap);

OE_ENCLAVELIBC_PRINTF_FORMAT(3, 4)
int oe_snprintf(char* str, size_t size, const char* format, ...);

int oe_vprintf(const char* format, oe_va_list ap);

OE_ENCLAVELIBC_PRINTF_FORMAT(1, 2)
int oe_printf(const char* format, ...);

#if defined(OE_ENCLAVELIBC_NEED_STDC_NAMES)

typedef OE_FILE FILE;
#define stdin oe_stdin
#define stdout oe_stdout
#define stderr oe_stderr

OE_ENCLAVELIBC_INLINE
int vsnprintf(char* str, size_t size, const char* format, va_list ap)
{
    return oe_vsnprintf(str, size, format, ap);
}

OE_ENCLAVELIBC_PRINTF_FORMAT(3, 4)
OE_ENCLAVELIBC_INLINE
int snprintf(char* str, size_t size, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    return oe_vsnprintf(str, size, format, ap);
    va_end(ap);
}

OE_ENCLAVELIBC_INLINE
int vprintf(const char* format, va_list ap)
{
    return oe_vprintf(format, ap);
}

OE_ENCLAVELIBC_PRINTF_FORMAT(1, 2)
OE_ENCLAVELIBC_INLINE
int printf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    return oe_vprintf(format, ap);
    va_end(ap);
}

#endif /* defined(OE_ENCLAVELIBC_NEED_STDC_NAMES) */

OE_ENCLAVELIBC_EXTERNC_END

#endif /* _OE_ENCLAVELIBC_STDIO_H */
