// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CORELIBC_PTHREAD_H
#define _OE_CORELIBC_PTHREAD_H

#include "bits/common.h"

#if defined(OE_CORELIBC_NEED_STDC_NAMES)

typedef struct _pthread_mutex
{
    uint64_t __impl[4];
} pthread_mutex_t;

#endif /* defined(OE_CORELIBC_NEED_STDC_NAMES) */

#endif /* _OE_CORELIBC_PTHREAD_H */
