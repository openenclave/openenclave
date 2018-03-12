// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _stdc_args_h
#define _stdc_args_h

#include <openenclave/types.h>

typedef struct _TestMutexArgs
{
    size_t count1;
    size_t count2;
} TestMutexArgs;

typedef struct _WaitArgs
{
    /* The number of threads that will call wait */
    size_t numThreads;
} WaitArgs;

#endif /* _stdc_args_h */
