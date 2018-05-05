// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_DEFS_H
#define _OE_DEFS_H

#include "bits/constants_x64.inc"

#if !defined(_MSC_VER) && !defined(__GNUC__)
#error "Unsupported platform"
#endif

#if defined(__GNUC__) && (__GNUC__ >= 4)
#define OE_PRINTF_FORMAT(N, M) __attribute__((format(printf, N, M)))
#else
#define OE_PRINTF_FORMAT(N, M) /* empty */
#endif

#define OE_DEPRECATED(MSG) __attribute__((deprecated(MSG)))

#define OE_UNUSED(P) (void)(P)

#if defined(__linux__)
#define OE_ALWAYS_INLINE __attribute__((always_inline))
#elif defined(_WIN32)
#define OE_ALWAYS_INLINE __forceinline
#endif

#ifdef _MSC_VER
#define OE_NEVER_INLINE __declspec(noinline)
#elif __GNUC__
#define OE_NEVER_INLINE __attribute__((noinline))
#endif

#ifdef _MSC_VER
#define OE_INLINE static __inline
#elif __GNUC__
#define OE_INLINE static __inline__
#endif

#if defined(__cplusplus)
#define OE_EXTERNC extern "C"
#define OE_EXTERNC_BEGIN extern "C" {
#define OE_EXTERNC_END }
#else
#define OE_EXTERNC
#define OE_EXTERNC_BEGIN
#define OE_EXTERNC_END
#endif

/*
 * Export a symbol, so it can be found as a dynamic symbol later for
 * ecall/ocall usage.
 */
#ifdef __GNUC__
#define OE_EXPORT __attribute__((visibility("default")))
#elif _MSC_VER
#define OE_EXPORT \
    __declspec(dllexport) /* TODO #54: Find the right mechanism here */
#else
#error "OE_EXPORT unimplemented"
#endif

/*
 * Define packed types, such as:
 *     OE_PACK_BEGIN
 *     struct foo {int a,b};
 *     OE_PACK_END
 */
#if defined(__GNUC__)
#define OE_PACK_BEGIN _Pragma("pack(push, 1)")
#define OE_PACK_END _Pragma("pack(pop)")
#elif _MSC_VER
#define OE_PACK_BEGIN __pragma(pack(push, 1))
#define OE_PACK_END __pragma(pack(pop))
#else
#error "OE_PACK_BEGIN and OE_PACK_END not implemented"
#endif

#ifdef __GNUC__
#define OE_ALIGNED(BYTES) __attribute__((aligned(BYTES)))
#elif _MSC_VER
#define OE_ALIGNED(BYTES) __declspec(align(BYTES))
#else
#error OE_ALIGNED not implemented
#endif

#ifdef __GNUC__
#define OE_UNUSED_ATTRIBUTE __attribute__((unused))
#elif _MSC_VER
#define OE_UNUSED_ATTRIBUTE
#else
#error OE_UNUSED_ATTRIBUTE not implemented
#endif

#define OE_COUNTOF(ARR) (sizeof(ARR) / sizeof((ARR)[0]))

#ifdef __GNUC__
#define OE_OFFSETOF(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#elif _MSC_VER
#ifdef __cplusplus
#define OE_OFFSETOF(TYPE, MEMBER) \
    ((size_t) & reinterpret_cast<char const volatile&>((((TYPE*)0)->MEMBER)))
#else
#define OE_OFFSETOF(TYPE, MEMBER) ((size_t) & (((TYPE*)0)->MEMBER))
#endif
#else
#error OE_OFFSETOF not implemented
#endif

#define OE_FIELD_SIZE(TYPE, FIELD) (sizeof(((TYPE*)0)->FIELD))

#define __OE_CONCAT(X, Y) X##Y
#define OE_CONCAT(X, Y) __OE_CONCAT(X, Y)

#define OE_CHECK_SIZE(N, M)          \
    typedef unsigned char OE_CONCAT( \
        __OE_CHECK_SIZE, __LINE__)[((N) == (M)) ? 1 : -1] OE_UNUSED_ATTRIBUTE

#define OE_STATIC_ASSERT(COND)       \
    typedef unsigned char OE_CONCAT( \
        __OE_STATIC_ASSERT, __LINE__)[(COND) ? 1 : -1] OE_UNUSED_ATTRIBUTE

#define OE_TRACE \
    printf("OE_TRACE: %s(%u): %s()\n", __FILE__, __LINE__, __FUNCTION__)

#ifndef NULL
#ifdef __cplusplus
#define NULL 0L
#else
#define NULL ((void*)0)
#endif
#endif

#define OE_WEAK_ALIAS(OLD, NEW) \
    extern __typeof(OLD) NEW __attribute__((weak, alias(#OLD)))

#ifdef _WIN32
/* nonstandard extension used: zero-sized array in struct/union */
#define OE_ZERO_SIZED_ARRAY __pragma(warning(suppress : 4200))
#else
#define OE_ZERO_SIZED_ARRAY /* empty */
#endif

#define __OE_PASTE(PREFIX, NAME) PREFIX##NAME
#define OE_PASTE(PREFIX, NAME) __OE_PASTE(PREFIX, NAME)

/*
 * Are we missing proper type usage? This might be tedious to fix.
 * TODO #55: Do a CR on proper used of integer types.
 */
// OE_STATIC_ASSERT(sizeof(long) == sizeof(long long));

// OE_STATIC_ASSERT(sizeof(long) == sizeof(void*));

#endif /* _OE_DEFS_H */
