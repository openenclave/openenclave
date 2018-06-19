// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVELIBC_STDIO_H
#define _ENCLAVELIBC_STDIO_H

#include "bits/common.h"
#include "stdarg.h"

OE_EXTERNC_BEGIN

OE_INLINE
int vsnprintf(char* str, size_t size, const char* format, va_list ap)
{
    return oe_vsnprintf(str, size, format, ap);
}

OE_PRINTF_FORMAT(3, 4)
OE_INLINE
int snprintf(char* str, size_t size, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    return oe_vsnprintf(str, size, format, ap);
    va_end(ap);
}

OE_INLINE
int vprintf(const char* format, va_list ap)
{
    return oe_vprintf(format, ap);
}

OE_PRINTF_FORMAT(1, 2)
OE_INLINE
int printf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    return oe_vprintf(format, ap);
    va_end(ap);
}

OE_EXTERNC_END

#endif /* _ENCLAVELIBC_STDIO_H */
