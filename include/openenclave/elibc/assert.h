// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ELIBC_ASSERT_H
#define _ELIBC_ASSERT_H

#include "bits/common.h"

void __elibc_assert_fail(
    const char* expr,
    const char* file,
    int line,
    const char* func);

// clang-format off
#ifndef NDEBUG
#define elibc_assert(EXPR)                                                \
    do                                                                      \
    {                                                                       \
        if (!(EXPR))                                                        \
            __elibc_assert_fail(#EXPR, __FILE__, __LINE__, __FUNCTION__); \
    } while (0)
#else
#define elibc_assert(EXPR)
#endif
// clang-format on

#if defined(ELIBC_NEED_STDC_NAMES)

#define assert(EXPR) elibc_assert(EXPR)

#endif /* defined(ELIBC_NEED_STDC_NAMES) */

#endif /* _ELIBC_ASSERT_H */
