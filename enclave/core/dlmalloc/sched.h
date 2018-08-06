// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CORE_DLMALLOC_SCHED_H
#define _OE_CORE_DLMALLOC_SCHED_H

#include <openenclave/bits/defs.h>

OE_INLINE int sched_yield(void)
{
    asm volatile("pause");
    return 0;
}

#endif /* _OE_CORE_DLMALLOC_SCHED_H */
