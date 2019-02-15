// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ATOMIC_H
#define _OE_ATOMIC_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

#if defined(_MSC_VER)
#pragma intrinsic(_InterlockedIncrement64)
#pragma intrinsic(_InterlockedDecrement64)
__int64 _InterlockedIncrement64(__int64* lpAddend);
__int64 _InterlockedDecrement64(__int64* lpAddend);
#endif

/* Atomically increment **x** and return its new value */
OE_INLINE uint64_t oe_atomic_increment(volatile uint64_t* x)
{
#if defined(__GNUC__)
    return __sync_add_and_fetch(x, 1);
#elif defined(_MSC_VER)
    return _InterlockedIncrement64((__int64*)x);
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
    return _InterlockedDecrement64((__int64*)x);
#else
#error "unsupported"
#endif
}

#endif /* _OE_ATOMIC_H */
