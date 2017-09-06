#ifndef __ELIBC_LIMITS_H
#define __ELIBC_LIMITS_H

#include <features.h>
#include <bits/alltypes.h>

#define INT8_MIN (-1-0x7f)

#define INT16_MIN (-1-0x7fff)

#define INT32_MIN (-1-0x7fffffff)

#define INT64_MIN (-1-0x7fffffffffffffff)

#define INT8_MAX (0x7f)

#define INT16_MAX (0x7fff)

#define INT32_MAX (0x7fffffff)

#define INT64_MAX (0x7fffffffffffffff)

#define UINT8_MAX (0xff)

#define UINT16_MAX (0xffff)

#define UINT32_MAX (0xffffffffu)

#define UINT64_MAX (0xffffffffffffffffu)

#define SIZE_MAX UINT64_MAX

#define INTMAX_MAX INT64_MAX

#define LONG_MAX  0x7fffffffffffffffL

#define LLONG_MAX  0x7fffffffffffffffLL

#define CHAR_BIT 8

#define SCHAR_MIN (-128)

#define SCHAR_MAX 127

#define UCHAR_MAX 255

#define SHRT_MIN  (-1-0x7fff)

#define SHRT_MAX  0x7fff

#define USHRT_MAX 0xffff

#define INT_MIN  (-1-0x7fffffff)

#define INT_MAX  0x7fffffff

#define UINT_MAX 0xffffffffU

#define LONG_MIN (-LONG_MAX-1)

#define ULONG_MAX (2UL*LONG_MAX+1)

#define LLONG_MIN (-LLONG_MAX-1)

#define ULLONG_MAX (2ULL*LLONG_MAX+1)

#define CHAR_MIN (-128)

#define CHAR_MAX 127

#define NL_ARGMAX 9

#define MB_LEN_MAX 4

#define TZNAME_MAX 6

#define NAME_MAX 255

#define PATH_MAX 4096

#define SSIZE_MAX INT64_MAX

#define SIZE_MAX UINT64_MAX

#define INT_FAST16_MIN INT32_MIN

#define INT_FAST32_MIN INT32_MIN

#define INT_FAST16_MAX INT32_MAX

#define INT_FAST32_MAX INT32_MAX

#define UINT_FAST16_MAX UINT32_MAX

#define UINT_FAST32_MAX UINT32_MAX

#define INTPTR_MIN INT64_MIN

#define INTPTR_MAX INT64_MAX

#define UINTPTR_MAX UINT64_MAX

#define PTRDIFF_MIN INT64_MIN

#define PTRDIFF_MAX INT64_MAX

#endif /* __ELIBC_LIMITS_H */
