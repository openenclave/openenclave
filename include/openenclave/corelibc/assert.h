// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ASSERT_H
#define _OE_ASSERT_H

/*
**==============================================================================
**
** OE names:
**
**==============================================================================
*/

/* Include the oe_assert() definition from enclave.h. */
#include <openenclave/enclave.h>

/*
**==============================================================================
**
** Standard-C names:
**
**==============================================================================
*/

#if defined(OE_NEED_STDC_NAMES)

#define assert oe_assert

#define __assert_fail __oe_assert_fail

#endif /* defined(OE_NEED_STDC_NAMES) */

#endif /* _OE_ASSERT_H */
