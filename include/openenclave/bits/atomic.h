// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ATOMIC_H
#define _OE_ATOMIC_H

#include <openenclave/defs.h>
#include <openenclave/types.h>

#if defined(_MSC_VER)
#include <windows.h>
#endif

/* Atomically increment **x** and return its new value */
OE_INLINE uint64_t oe_atomic_increment(volatile uint64_t* x)
{
#if defined(__GNUC__)
    return __sync_add_and_fetch(x, 1);
#elif defined(_MSC_VER)
    return InterlockedIncrement64(x);
#else
#error "unsupported"
#endif
}

/* Atomically decrement **x** and return its new value */
OE_INLINE uint64_t oe_atomic_decrement(volatile uint64_t* x)
{
#if defined(__GNUC__)
    return __sync_sub_and_fetch(x, 1);
#elif defined(_MSC_VER)
    return InterlockedDecrement64(x);
#else
#error "unsupported"
#endif
}

#endif /* _OE_ATOMIC_H */
