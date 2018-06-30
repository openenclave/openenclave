// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CORELIBC_COMMON_H
#define _OE_CORELIBC_COMMON_H

#if defined(__cplusplus)
#define OE_CORELIBC_EXTERNC extern "C"
#define OE_CORELIBC_EXTERNC_BEGIN extern "C" {
#define OE_CORELIBC_EXTERNC_END }
#else
#define OE_CORELIBC_EXTERNC
#define OE_CORELIBC_EXTERNC_BEGIN
#define OE_CORELIBC_EXTERNC_END
#endif

#if defined(__GNUC__)
#define OE_CORELIBC_PRINTF_FORMAT(N, M) __attribute__((format(printf, N, M)))
#endif

#define OE_CORELIBC_INLINE static __inline

#ifndef NULL
# ifdef __cplusplus
#   define NULL 0L
#else
#   define NULL ((void*)0)
# endif
#endif

OE_CORELIBC_EXTERNC_BEGIN

typedef long ssize_t;
typedef unsigned long size_t;
typedef long intptr_t;
typedef unsigned long uintptr_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long int64_t;
typedef unsigned long uint64_t;
typedef unsigned long uintptr_t;
typedef long ptrdiff_t;
typedef long time_t;
typedef __builtin_va_list oe_va_list;
typedef oe_va_list va_list;
typedef long suseconds_t;
typedef int clockid_t;

OE_CORELIBC_EXTERNC_END

#endif /* _OE_CORELIBC_COMMON_H */
