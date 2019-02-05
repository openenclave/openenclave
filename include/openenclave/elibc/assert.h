// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ASSERT_H
#define _OE_ASSERT_H

#if defined(OE_NEED_STDC_NAMES)

#include <openenclave/enclave.h>
#define assert(EXPR) oe_assert(EXPR)
#define __assert_fail(EXPR) __oe_assert_fail(EXPR)

#endif /* defined(OE_NEED_STDC_NAMES) */

#endif /* _OE_ASSERT_H */
