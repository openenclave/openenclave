#ifndef _OE_ENCLAVELIBC_ASSERT_H
#define _OE_ENCLAVELIBC_ASSERT_H

#include "bits/common.h"

void __oe_assert_fail(
    const char* expr,
    const char* file,
    int line,
    const char* func);

#if !defined(oe_assert)
#ifndef NDEBUG
#define oe_assert(EXPR)                                                \
    do                                                                 \
    {                                                                  \
        if (!(EXPR))                                                   \
            __oe_assert_fail(#EXPR, __FILE__, __LINE__, __FUNCTION__); \
    } while (0)
#else
#define oe_assert(EXPR)
#endif
#endif /* !defined(oe_assert) */

#if defined(OE_ENCLAVELIBC_NEED_STDC_NAMES)

#define assert(EXPR) oe_assert(EXPR)

#endif /* defined(OE_ENCLAVELIBC_NEED_STDC_NAMES) */

#endif /* _OE_ENCLAVELIBC_ASSERT_H */
