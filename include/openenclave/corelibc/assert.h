// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ASSERT_H
#define _OE_ASSERT_H

/* Defined here in addition to openenclave/enclave.h (public API),
 * for assert.h parity and so that use of corelibc/assert.h doesn't
 * pull in that entire header which contains oeenclave methods.
 */
void __oe_assert_fail(
    const char* expr,
    const char* file,
    int line,
    const char* func);

/* Ideally, this should be defined once in bits and included here and
 * in enclave.h, but we also use enclave.h as the canonical reference
 * for the public API surface, so oe_assert needs to be defined there
 * as well just for visibility.
 */
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

#if defined(OE_NEED_STDC_NAMES)

#define assert(EXPR) oe_assert(EXPR)
#define __assert_fail(EXPR) __oe_assert_fail(EXPR)

#endif /* defined(OE_NEED_STDC_NAMES) */

#endif /* _OE_ASSERT_H */
