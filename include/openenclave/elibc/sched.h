// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SCHED_H
#define _OE_SCHED_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

int oe_sched_yield(void);

#if defined(OE_NEED_STDC_NAMES)

OE_INLINE int sched_yield(void)
{
    return oe_sched_yield();
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_SCHED_H */
