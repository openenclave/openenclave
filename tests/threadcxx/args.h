// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _stdc_args_h
#define _stdc_args_h

#include <openenclave/bits/types.h>

typedef struct _TestMutexCxxArgs
{
    size_t count;
    size_t numThreads;
    size_t ID;
    // size_t count2;
} TestMutexCxxArgs;

typedef struct _WaitCxxArgs
{
    /* The number of threads that will call wait */
    size_t numThreads;
} WaitCxxArgs;

#endif /* _stdc_args_h */
