// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _libcxxthrd_args_h
#define _libcxxthrd_args_h

static std::atomic_flag _lock = ATOMIC_FLAG_INIT;
static void _acquire_lock()
{
    while (_lock.test_and_set(std::memory_order_acquire))
        ;
}

static void _release_lock()
{
    _lock.clear(std::memory_order_release);
}

#endif /* _libcxxthrd_args_h */
