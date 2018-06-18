#ifndef _OE_MBEDTLS_STDARG_H
#define _OE_MBEDTLS_STDARG_H

#include "bits/alltypes.h"
#include "bits/mbedtls_libc.h"

#define va_start __builtin_va_start
#define va_arg __builtin_va_arg
#define va_end __builtin_va_end
#define va_copy __builtin_va_copy

#endif /* _OE_MBEDTLS_STDARG_H */
