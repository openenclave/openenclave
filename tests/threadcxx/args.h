// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _THREADCXX_ARGS_H
#define _THREADCXX_ARGS_H

#include <openenclave/bits/types.h>

typedef struct _TestMutexCxxArgs
{
    size_t count1;
    size_t count2;
    size_t numThreads;
} TestMutexCxxArgs;

typedef struct _WaitCxxArgs
{
    /* The number of threads that will call wait */
    size_t numThreads;
} WaitCxxArgs;

#endif /* THREADCXX_ARGS_H */
