// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVELIBC_LIMITS_H
#define _OE_ENCLAVELIBC_LIMITS_H

#include "bits/common.h"

#define SCHAR_MIN (-128)
#define SCHAR_MAX 127
#define UCHAR_MAX 255
#define CHAR_MIN (-128)
#define CHAR_MAX 127
#define CHAR_BIT 8

#define SHRT_MIN (-1-0x7fff)
#define SHRT_MAX 0x7fff
#define USHRT_MAX 0xffff

#define INT_MIN  (-1-0x7fffffff)
#define INT_MAX  0x7fffffff
#define UINT_MAX 0xffffffffU

#define LONG_MAX 0x7fffffffffffffffL
#define LONG_MIN (-LONG_MAX-1)
#define ULONG_MAX (2UL*LONG_MAX+1)

#define LLONG_MAX 0x7fffffffffffffffLL
#define LLONG_MIN (-LLONG_MAX-1)
#define ULLONG_MAX (2ULL*LLONG_MAX+1)

#endif /* _OE_ENCLAVELIBC_LIMITS_H */
