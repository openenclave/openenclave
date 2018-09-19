// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _RUNTEST_ARGS_H
#define _RUNTEST_ARGS_H

#include <atomic>

typedef struct _Args
{
    const char* test;
    int ret;
} Args;

static inline void _acquire_lock(std::atomic_flag* lock)
{
    while (lock->test_and_set(std::memory_order_acquire))
        ;
}

static inline void _release_lock(std::atomic_flag* lock)
{
    lock->clear(std::memory_order_release);
}

#endif /* _RUNTEST_ARGS_H */
