// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ATOMIC_H
#define _OE_ATOMIC_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

#if defined(_MSC_VER)
#pragma intrinsic(_InterlockedIncrement64)
#pragma intrinsic(_InterlockedDecrement64)
#pragma intrinsic(_InterlockedCompareExchange64)
#pragma intrinsic(_InterlockedCompareExchangePointer)
__int64 _InterlockedIncrement64(__int64* lpAddend);
__int64 _InterlockedDecrement64(__int64* lpAddend);
__int64 _InterlockedCompareExchange64(
    __int64 volatile* Dest,
    __int64 val,
    __int64 old);
void* _InterlockedCompareExchangePointer(
    void* volatile* Dest,
    void* newptr,
    void* old);
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

OE_INLINE
bool oe_atomic_compare_and_swap(
    int64_t volatile* dest,
    int64_t old,
    int64_t newval)
{
#if defined(__GNUC__)
    return __atomic_compare_exchange_n(
        dest, &old, newval, 1, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
#elif defined(_MSC_VER)
    return _InterlockedCompareExchange64(dest, newval, old) == old;
#else
#error "unsupported"
#endif
}

OE_INLINE
bool oe_atomic_compare_and_swap_ptr(
    void* volatile* dest,
    void* old,
    void* newptr)
{
#if defined(__GNUC__)
    return __atomic_compare_exchange_n(
        dest, &old, newptr, 1, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
#elif defined(_MSC_VER)
    return _InterlockedCompareExchangePointer(dest, newptr, old) == old;
#else
#error "unsupported"
#endif
}

#endif /* _OE_ATOMIC_H */
