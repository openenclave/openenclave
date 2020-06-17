// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_BITS_DEFS_H
#define _OE_BITS_DEFS_H

#if !defined(_MSC_VER) && !defined(__GNUC__)
#error "Unsupported platform"
#endif

#if !defined(_WIN64) && !defined(__x86_64__) && !defined(__aarch64__)
#error "32-bit targets are currently not supported"
#endif

/* OE_API_VERSION */
#ifndef OE_API_VERSION
#define OE_API_VERSION 2
#endif

/* OE_NO_RETURN */
#if defined(__GNUC__)
#define OE_NO_RETURN __attribute__((__noreturn__))
#else
#define OE_NO_RETURN
#endif

/* OE_PRINTF_FORMAT */
#if defined(__GNUC__) && (__GNUC__ >= 4)
#define OE_PRINTF_FORMAT(N, M) __attribute__((format(printf, N, M)))
#else
#define OE_PRINTF_FORMAT(N, M) /* empty */
#endif

/* OE_UNUSED */
#define OE_UNUSED(P) (void)(P)

/* OE_USED */
#if defined(__GNUC__)
#define OE_USED __attribute__((__used__))
#else
#define OE_USED /* empty */
#endif

/* OE_ALWAYS_INLINE */
#if defined(__GNUC__)
#define OE_ALWAYS_INLINE __attribute__((always_inline))
#elif defined(_MSC_VER)
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

#if defined(__GNUC__) || defined(__clang__)
#define OE_RETURNS_TWICE __attribute__((returns_twice))
#else
#define OE_RETURNS_TWICE
#endif

#ifdef _MSC_VER
#define OE_NO_OPTIMIZE_BEGIN __pragma(optimize("", off))
#define OE_NO_OPTIMIZE_END __pragma(optimize("", on))
#elif __clang__
#define OE_NO_OPTIMIZE_BEGIN _Pragma("clang optimize off")
#define OE_NO_OPTIMIZE_END _Pragma("clang optimize on")
#elif __GNUC__
#define OE_NO_OPTIMIZE_BEGIN \
    _Pragma("GCC push_options") _Pragma("GCC optimize(\"O0\")")
#define OE_NO_OPTIMIZE_END _Pragma("GCC pop_options")
#else
#error "OE_NO_OPTIMIZE_BEGIN and OE_NO_OPTIMIZE_END not implemented"
#endif

#if defined(__cplusplus)
#define OE_EXTERNC extern "C"
#define OE_EXTERNC_BEGIN \
    extern "C"           \
    {
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
 * Export a constant symbol.
 * In C, the symbol is annotated with OE_EXPORT const.
 * In C++, const symbols by default have internal linkage.
 * Therefore, the symbol is annotated with OE_EXPORT extern const
 * to ensure extern linkage and prevent compiler warnings.
 */
#if defined(__cplusplus)
#define OE_EXPORT_CONST OE_EXPORT extern const
#else
#define OE_EXPORT_CONST OE_EXPORT const
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

/* The maxiumum value for a four-byte enum tag */
#define OE_ENUM_MAX 0xffffffff

/* OE_DEPRECATED */
#if defined(__GNUC__)
#define OE_DEPRECATED(FUNC, MSG) FUNC __attribute__((deprecated(MSG)))
#elif defined(_MSC_VER)
#define OE_DEPRECATED(FUNC, MSG) __declspec(deprecated(MSG)) FUNC
#else
#define OE_DEPRECATED(FUNC, MSG) FUNC
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

/*
 * Intended for use by other bits headers, not a part of the public API surface.
 */

/* OE_ZERO_SIZED_ARRAY */
#ifdef _MSC_VER
/* nonstandard extension used: zero-sized array in struct/union */
#define OE_ZERO_SIZED_ARRAY __pragma(warning(suppress : 4200))
#else
#define OE_ZERO_SIZED_ARRAY /* empty */
#endif

/* OE_UNUSED_ATTRIBUTE */
#ifdef __GNUC__
#define OE_UNUSED_ATTRIBUTE __attribute__((unused))
#elif _MSC_VER
#define OE_UNUSED_ATTRIBUTE
#else
#error OE_UNUSED_ATTRIBUTE not implemented
#endif

/* OE_CONCAT */
#define __OE_CONCAT(X, Y) X##Y
#define OE_CONCAT(X, Y) __OE_CONCAT(X, Y)

/* OE_STATIC_ASSERT */
#define OE_STATIC_ASSERT(COND)       \
    typedef unsigned char OE_CONCAT( \
        __OE_STATIC_ASSERT, __LINE__)[(COND) ? 1 : -1] OE_UNUSED_ATTRIBUTE

/* OE_CHECK_SIZE */
#define OE_CHECK_SIZE(N, M)          \
    typedef unsigned char OE_CONCAT( \
        __OE_CHECK_SIZE, __LINE__)[((N) == (M)) ? 1 : -1] OE_UNUSED_ATTRIBUTE

/* OE_FIELD_SIZE */
#define OE_FIELD_SIZE(TYPE, FIELD) (sizeof(((TYPE*)0)->FIELD))

/* OE_WEAK_ALIAS */
#ifdef __GNUC__
#define OE_WEAK_ALIAS(OLD, NEW) \
    extern __typeof(OLD) NEW __attribute__((__weak__, alias(#OLD)))
#elif _MSC_VER
#define OE_WEAK_ALIAS(OLD, NEW) \
    __pragma(comment(linker, "/alternatename:" #NEW "=" #OLD))
#else
#error OE_WEAK_ALIAS not implemented
#endif

/* OE_WEAK */
#ifdef __GNUC__
#define OE_WEAK __attribute__((weak))
#else
#define OE_WEAK
#endif

/* OE_PAGE_SIZE */
#define OE_PAGE_SIZE 0x1000

/* OE_CHECK_FIELD */
#define OE_CHECK_FIELD(T1, T2, F)                               \
    OE_STATIC_ASSERT(OE_OFFSETOF(T1, F) == OE_OFFSETOF(T2, F)); \
    OE_STATIC_ASSERT(sizeof(((T1*)0)->F) == sizeof(((T2*)0)->F));

// Statically defined functions which are aliased should be marked as unused
// to prevent compiler warnings in GCC and Clang
#if __GNUC__
#define OE_UNUSED_FUNC __attribute__((unused))
#elif _MSC_VER
#define OE_UNUSED_FUNC
#else
#error OE_UNUSED_FUNC not implemented
#endif

#endif /* _OE_BITS_DEFS_H */
