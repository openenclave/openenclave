#ifndef __ELIBC_STDARG_H
#define __ELIBC_STDARG_H

#include <features.h>
#include <bits/alltypes.h>

__ELIBC_BEGIN

#define va_start(ap, last) __builtin_va_start((ap), last)

#define va_end __builtin_va_end

#define va_arg __builtin_va_arg

#define va_copy(dst, src) __builtin_va_copy((dst), (src))

__ELIBC_END

#endif /* __ELIBC_STDARG_H */
