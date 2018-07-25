// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_DEFS_H
#define _OE_BITS_DEFS_H

#if !defined(_MSC_VER) && !defined(__GNUC__)
#error "Unsupported platform"
#endif

/* OE_PRINTF_FORMAT */
#if defined(__GNUC__) && (__GNUC__ >= 4)
#define OE_PRINTF_FORMAT(N, M) __attribute__((format(printf, N, M)))
#else
#define OE_PRINTF_FORMAT(N, M) /* empty */
#endif

/* OE_UNUSED */
#define OE_UNUSED(P) (void)(P)

/* OE_ALWAYS_INLINE */
#if defined(__linux__)
#define OE_ALWAYS_INLINE __attribute__((always_inline))
#elif defined(_WIN32)
#define OE_ALWAYS_INLINE __forceinline
#endif

/* OE_NEVER_INLINE */
#ifdef _MSC_VER
#define OE_NEVER_INLINE __declspec(noinline)
#elif __GNUC__
#define OE_NEVER_INLINE __attribute__((noinline))
#endif

/* OE_INLINE */
#ifdef _MSC_VER
#define OE_INLINE static __inline
#elif __GNUC__
#define OE_INLINE static __inline__
#endif

/* OE_EXTERNC, OE_EXTERNC_BEGIN, OE_EXTERNC_END */
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
#define OE_EXPORT __declspec(dllexport)
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

/* OE_ALIGNED */
#ifdef __GNUC__
#define OE_ALIGNED(BYTES) __attribute__((aligned(BYTES)))
#elif _MSC_VER
#define OE_ALIGNED(BYTES) __declspec(align(BYTES))
#else
#error OE_ALIGNED not implemented
#endif

/* OE_COUNTOF */
#define OE_COUNTOF(ARR) (sizeof(ARR) / sizeof((ARR)[0]))

/* OE_OFFSETOF */
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

/* NULL */
#ifndef NULL
#ifdef __cplusplus
#define NULL 0L
#else
#define NULL ((void*)0)
#endif
#endif

/* OE_ECALL */
#define OE_ECALL OE_EXTERNC OE_EXPORT __attribute__((section(".ecall")))

/* OE_OCALL */
#define OE_OCALL OE_EXTERNC OE_EXPORT

/* OE_ENUM_MAX - the max value for an enumerated tag */
#define OE_ENUM_MAX 0xffffffff

#endif /* _OE_BITS_DEFS_H */
