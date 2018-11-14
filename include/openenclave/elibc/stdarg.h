// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ELIBC_STDARG_H
#define _ELIBC_STDARG_H

#include "bits/common.h"

#if defined(_MSC_VER)
typedef char* elibc_va_list;
#define elibc_va_start(ap, x) __va_start(&ap, x)
#define elibc_va_arg(ap, type) \
    *((type*)((ap += sizeof(__int64)) - sizeof(__int64)))
#define elibc_va_end(ap) (ap = (va_list)0)
#define elibc_va_copy(ap1, ap2) (ap1 = ap2)
#elif defined(__linux__)
#define elibc_va_start __builtin_va_start
#define elibc_va_arg __builtin_va_arg
#define elibc_va_end __builtin_va_end
#define elibc_va_copy __builtin_va_copy
#endif

#if defined(ELIBC_NEED_STDC_NAMES)

#define va_start elibc_va_start
#define va_arg elibc_va_arg
#define va_end elibc_va_end
#define va_copy elibc_va_copy

#endif /* defined(ELIBC_NEED_STDC_NAMES) */

#endif /* _ELIBC_STDARG_H */
