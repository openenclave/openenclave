// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef OSSL_INTERNAL_REFCOUNT_H
#define OSSL_INTERNAL_REFCOUNT_H

typedef int CRYPTO_REF_COUNT;

static __inline__ int CRYPTO_UP_REF(int* val, int* ret, void* lock)
{
    *ret = __atomic_fetch_add(val, 1, __ATOMIC_RELAXED) + 1;
    (void)lock;
    return 1;
}

static __inline__ int CRYPTO_DOWN_REF(int* val, int* ret, void* lock)
{
    *ret = __atomic_fetch_sub(val, 1, __ATOMIC_RELAXED) - 1;
    if (*ret == 0)
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
    (void)lock;
    return 1;
}

#endif
