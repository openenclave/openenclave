// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _THREADCXX_ARGS_H
#define _THREADCXX_ARGS_H

#include <openenclave/bits/types.h>

typedef struct _test_mutex_cxx_args
{
    size_t count1;
    size_t count2;
    size_t num_threads;
} TestMutexCxxArgs;

typedef struct _wait_cxx_args
{
    /* The number of threads that will call wait */
    size_t num_threads;
} WaitCxxArgs;

#endif /* THREADCXX_ARGS_H */
