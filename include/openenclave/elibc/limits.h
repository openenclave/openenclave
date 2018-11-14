// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ELIBC_LIMITS_H
#define _ELIBC_LIMITS_H

#include "bits/common.h"

#define ELIBC_SCHAR_MIN (-128)
#define ELIBC_SCHAR_MAX 127
#define ELIBC_UCHAR_MAX 255
#define ELIBC_CHAR_MIN (-128)
#define ELIBC_CHAR_MAX 127
#define ELIBC_CHAR_BIT 8
#define ELIBC_SHRT_MIN (-1 - 0x7fff)
#define ELIBC_SHRT_MAX 0x7fff
#define ELIBC_USHRT_MAX 0xffff
#define ELIBC_INT_MIN (-1 - 0x7fffffff)
#define ELIBC_INT_MAX 0x7fffffff
#define ELIBC_UINT_MAX 0xffffffffU

#ifdef _MSC_VER
#define ELIBC_LONG_MAX 0x7fffffffL
#elif __linux__
#define ELIBC_LONG_MAX 0x7fffffffffffffffL
#endif

#define ELIBC_LONG_MIN (-ELIBC_LONG_MAX - 1)
#define ELIBC_ULONG_MAX (2UL * ELIBC_LONG_MAX + 1)
#define ELIBC_LLONG_MAX 0x7fffffffffffffffLL
#define ELIBC_LLONG_MIN (-ELIBC_LLONG_MAX - 1)
#define ELIBC_ULLONG_MAX (2ULL * ELIBC_LLONG_MAX + 1)

#if defined(ELIBC_NEED_STDC_NAMES)

#define SCHAR_MIN ELIBC_SCHAR_MIN
#define SCHAR_MAX ELIBC_SCHAR_MAX
#define UCHAR_MAX ELIBC_UCHAR_MAX
#define CHAR_MIN ELIBC_CHAR_MIN
#define CHAR_MAX ELIBC_CHAR_MAX
#define CHAR_BIT ELIBC_CHAR_BIT
#define SHRT_MIN ELIBC_SHRT_MIN
#define SHRT_MAX ELIBC_SHRT_MAX
#define USHRT_MAX ELIBC_USHRT_MAX
#define INT_MIN ELIBC_INT_MIN
#define INT_MAX ELIBC_INT_MAX
#define UINT_MAX ELIBC_UINT_MAX
#define LONG_MAX ELIBC_LONG_MAX
#define LONG_MIN ELIBC_LONG_MIN
#define ULONG_MAX ELIBC_ULONG_MAX
#define LLONG_MAX ELIBC_LLONG_MAX
#define LLONG_MIN ELIBC_LLONG_MIN
#define ULLONG_MAX ELIBC_ULLONG_MAX

#endif /* defined(ELIBC_NEED_STDC_NAMES) */

#endif /* _ELIBC_LIMITS_H */
