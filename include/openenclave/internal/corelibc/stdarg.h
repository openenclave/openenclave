// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CORELIBC_STDARG_H
#define _OE_CORELIBC_STDARG_H

#include "bits/common.h"

#define oe_va_start __builtin_va_start
#define oe_va_arg __builtin_va_arg
#define oe_va_end __builtin_va_end
#define oe_va_copy __builtin_va_copy

#if !defined(OE_CORELIBC_HIDE_STDC_NAMES)

#define va_start oe_va_start
#define va_arg oe_va_arg
#define va_end oe_va_end
#define va_copy oe_va_copy

#endif /* !defined(OE_CORELIBC_HIDE_STDC_NAMES) */

#endif /* _OE_CORELIBC_STDARG_H */
