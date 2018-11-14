// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ELIBC_STDIO_H
#define _ELIBC_STDIO_H

#include "bits/common.h"
#include "stdarg.h"

ELIBC_EXTERNC_BEGIN

typedef struct _ELIBC_IO_FILE ELIBC_FILE;
extern ELIBC_FILE* const elibc_stdin;
extern ELIBC_FILE* const elibc_stdout;
extern ELIBC_FILE* const elibc_stderr;

int elibc_vsnprintf(
    char* str,
    size_t size,
    const char* format,
    elibc_va_list ap);

ELIBC_PRINTF_FORMAT(3, 4)
int elibc_snprintf(char* str, size_t size, const char* format, ...);

int elibc_vprintf(const char* format, elibc_va_list ap);

ELIBC_PRINTF_FORMAT(1, 2)
int elibc_printf(const char* format, ...);

#if defined(ELIBC_NEED_STDC_NAMES)

typedef ELIBC_FILE FILE;
#define stdin elibc_stdin
#define stdout elibc_stdout
#define stderr elibc_stderr

ELIBC_INLINE
int vsnprintf(char* str, size_t size, const char* format, va_list ap)
{
    return elibc_vsnprintf(str, size, format, ap);
}

ELIBC_PRINTF_FORMAT(3, 4)
ELIBC_INLINE
int snprintf(char* str, size_t size, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    return elibc_vsnprintf(str, size, format, ap);
    va_end(ap);
}

ELIBC_INLINE
int vprintf(const char* format, va_list ap)
{
    return elibc_vprintf(format, ap);
}

ELIBC_PRINTF_FORMAT(1, 2)
ELIBC_INLINE
int printf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    return elibc_vprintf(format, ap);
    va_end(ap);
}

#endif /* defined(ELIBC_NEED_STDC_NAMES) */

ELIBC_EXTERNC_END

#endif /* _ELIBC_STDIO_H */
