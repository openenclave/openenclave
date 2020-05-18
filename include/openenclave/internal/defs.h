// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_DEFS_H
#define _OE_INTERNAL_DEFS_H

#include <openenclave/bits/defs.h>

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

/* OE_ZERO_SIZED_ARRAY */
#ifdef _WIN32
/* nonstandard extension used: zero-sized array in struct/union */
#define OE_ZERO_SIZED_ARRAY __pragma(warning(suppress : 4200))
#else
#define OE_ZERO_SIZED_ARRAY /* empty */
#endif

/* OE_CHECK_SIZE */
#define OE_CHECK_SIZE(N, M)          \
    typedef unsigned char OE_CONCAT( \
        __OE_CHECK_SIZE, __LINE__)[((N) == (M)) ? 1 : -1] OE_UNUSED_ATTRIBUTE

/* OE_FIELD_SIZE */
#define OE_FIELD_SIZE(TYPE, FIELD) (sizeof(((TYPE*)0)->FIELD))

/* OE_CHECK_FIELD */
#define OE_CHECK_FIELD(T1, T2, F)                               \
    OE_STATIC_ASSERT(OE_OFFSETOF(T1, F) == OE_OFFSETOF(T2, F)); \
    OE_STATIC_ASSERT(sizeof(((T1*)0)->F) == sizeof(((T2*)0)->F));

/* OE_PAGE_SIZE */
#define OE_PAGE_SIZE 0x1000

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

/* OE_FIELD_SIZE */
#define OE_FIELD_SIZE(TYPE, FIELD) (sizeof(((TYPE*)0)->FIELD))

#endif /* _OE_INTERNAL_DEFS_H */
