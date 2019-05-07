// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_STDARG_H
#define _OE_STDARG_H

#if defined(_MSC_VER)

typedef char* oe_va_list;
#define oe_va_start(ap, x) __va_start(&ap, x)
#define oe_va_arg(ap, type) \
    *((type*)((ap += sizeof(__int64)) - sizeof(__int64)))
#define oe_va_end(ap) (ap = (va_list)0)
#define oe_va_copy(ap1, ap2) (ap1 = ap2)

#elif defined(__linux__)

#define oe_va_list __builtin_va_list
#define oe_va_start __builtin_va_start
#define oe_va_arg __builtin_va_arg
#define oe_va_end __builtin_va_end
#define oe_va_copy __builtin_va_copy

#endif

#if defined(OE_NEED_STDC_NAMES) && !defined(_MSC_VER)

#define va_list oe_va_list
#define va_start oe_va_start
#define va_arg oe_va_arg
#define va_end oe_va_end
#define va_copy oe_va_copy

#endif /* defined(OE_NEED_STDC_NAMES) */

#endif /* _OE_STDARG_H */
