// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVELIBC_STDIO_H
#define _ENCLAVELIBC_STDIO_H

#include "bits/common.h"
#include "stdarg.h"

ENCLAVELIBC_INLINE
int vsnprintf(char* str, size_t size, const char* format, va_list ap)
{
    return __enclavelibc.vsnprintf(str, size, format, ap);
}

ENCLAVELIBC_INLINE
int snprintf(char* str, size_t size, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    return __enclavelibc.vsnprintf(str, size, format, ap);
    va_end(ap);
}

ENCLAVELIBC_INLINE
int vprintf(const char* format, va_list ap)
{
    return __enclavelibc.vprintf(format, ap);
}

ENCLAVELIBC_INLINE
int printf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    return __enclavelibc.vprintf(format, ap);
    va_end(ap);
}

#endif /* _ENCLAVELIBC_STDIO_H */
