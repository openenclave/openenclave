// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVELIBC_SCHED_H
#define _ENCLAVELIBC_SCHED_H

#include "bits/common.h"

OE_INLINE
int sched_yield(void)
{
    return oe_sched_yield();
}

#endif /* _ENCLAVELIBC_SCHED_H */
