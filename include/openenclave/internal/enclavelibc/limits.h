// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVELIBC_LIMITS_H
#define _OE_ENCLAVELIBC_LIMITS_H

#include "bits/common.h"

#define OE_SCHAR_MIN (-128)
#define OE_SCHAR_MAX 127
#define OE_UCHAR_MAX 255
#define OE_CHAR_MIN (-128)
#define OE_CHAR_MAX 127
#define OE_CHAR_BIT 8
#define OE_SHRT_MIN (-1 - 0x7fff)
#define OE_SHRT_MAX 0x7fff
#define OE_USHRT_MAX 0xffff
#define OE_INT_MIN (-1 - 0x7fffffff)
#define OE_INT_MAX 0x7fffffff
#define OE_UINT_MAX 0xffffffffU
#define OE_LONG_MAX 0x7fffffffffffffffL
#define OE_LONG_MIN (-LONG_MAX - 1)
#define OE_ULONG_MAX (2UL * LONG_MAX + 1)
#define OE_LLONG_MAX 0x7fffffffffffffffLL
#define OE_LLONG_MIN (-LLONG_MAX - 1)
#define OE_ULLONG_MAX (2ULL * LLONG_MAX + 1)

#if defined(OE_ENCLAVELIBC_NEED_STDC_NAMES)

#define SCHAR_MIN OE_SCHAR_MIN
#define SCHAR_MAX OE_SCHAR_MAX
#define UCHAR_MAX OE_UCHAR_MAX
#define CHAR_MIN OE_CHAR_MIN
#define CHAR_MAX OE_CHAR_MAX
#define CHAR_BIT OE_CHAR_BIT
#define SHRT_MIN OE_SHRT_MIN
#define SHRT_MAX OE_SHRT_MAX
#define USHRT_MAX OE_USHRT_MAX
#define INT_MIN OE_INT_MIN
#define INT_MAX OE_INT_MAX
#define UINT_MAX OE_UINT_MAX
#define LONG_MAX OE_LONG_MAX
#define LONG_MIN OE_LONG_MIN
#define ULONG_MAX OE_ULONG_MAX
#define LLONG_MAX OE_LLONG_MAX
#define LLONG_MIN OE_LLONG_MIN
#define ULLONG_MAX OE_ULLONG_MAX

#endif /* defined(OE_ENCLAVELIBC_NEED_STDC_NAMES) */

#endif /* _OE_ENCLAVELIBC_LIMITS_H */
