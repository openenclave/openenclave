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

#endif /* _OE_BITS_DEFS_H */
