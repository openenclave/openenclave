// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ELIBC_COMMON_H
#define _ELIBC_COMMON_H

#if defined(__cplusplus)
#define ELIBC_EXTERNC extern "C"
#define ELIBC_EXTERNC_BEGIN \
    extern "C"              \
    {
#define ELIBC_EXTERNC_END }
#else
#define ELIBC_EXTERNC
#define ELIBC_EXTERNC_BEGIN
#define ELIBC_EXTERNC_END
#endif

#if defined(__GNUC__)
#define ELIBC_PRINTF_FORMAT(N, M) __attribute__((format(printf, N, M)))
#else
#define ELIBC_PRINTF_FORMAT(N, M)
#endif

#define ELIBC_INLINE static __inline

#ifndef NULL
#ifdef __cplusplus
#define NULL 0L
#else
#define NULL ((void*)0)
#endif
#endif

#define ELIBC_NEED_STDC_NAMES

ELIBC_EXTERNC_BEGIN

#if defined(__linux__)
typedef __builtin_va_list elibc_va_list;
#elif (_MSC_VER)
typedef char* elibc_va_list;
#endif

#if defined(__GNUC__)
typedef long ssize_t;
typedef unsigned long size_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long int64_t;
typedef unsigned long uint64_t;
typedef unsigned long uintptr_t;
typedef long intptr_t;
typedef long ptrdiff_t;
typedef long time_t;
typedef long suseconds_t;
#elif defined(_MSC_VER)
typedef long long ssize_t;
typedef unsigned long long size_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef unsigned long long uintptr_t;
typedef long long intptr_t;
typedef long long ptrdiff_t;
typedef long long time_t;
typedef long long suseconds_t;
typedef struct _int128
{
    uint64_t x;
    uint64_t y;
} int128_t;
#endif

typedef int clockid_t;

#if defined(ELIBC_NEED_STDC_NAMES)

typedef elibc_va_list va_list;

#endif /* defined(ELIBC_NEED_STDC_NAMES) */

ELIBC_EXTERNC_END

#endif /* _ELIBC_COMMON_H */
