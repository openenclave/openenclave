#ifndef _OE_MBEDTLS_STDIO_H
#define _OE_MBEDTLS_STDIO_H

#include "bits/alltypes.h"
#include "bits/mbedtls_libc.h"
#include <stdarg.h>

static __inline
int vsnprintf(char* str, size_t size, const char* format, va_list ap)
{
    return __mbedtls_libc.vsnprintf(str, size, format, ap);
}

static __inline
int snprintf(char* str, size_t size, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    return __mbedtls_libc.vsnprintf(str, size, format, ap);
    va_end(ap);
}

static __inline
int vprintf(const char* format, va_list ap)
{
    return __mbedtls_libc.vprintf(format, ap);
}

static __inline
int printf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    return __mbedtls_libc.vprintf(format, ap);
    va_end(ap);
}

#endif /* _OE_MBEDTLS_STDIO_H */
