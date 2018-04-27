// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/utils.h>
#include <openenclave/enclave.h>

int OE_Once(OE_OnceType* once, void (*func)(void))
{
    if (!once)
        return -1;

    /* Double checked locking (DCLP). */
    int o = *once;

    /* DCLP Acquire barrier. */
    OE_ATOMIC_MEMORY_BARRIER_ACQUIRE();
    if (o == 0)
    {
        static OE_Spinlock _lock = OE_SPINLOCK_INITIALIZER;

        OE_SpinLock(&_lock);

        if (*once == 0)
        {
            if (func)
                func();

            /* DCLP Release barrier. */
            OE_ATOMIC_MEMORY_BARRIER_RELEASE();
            *once = 1;
        }

        OE_SpinUnlock(&_lock);
    }

    return 0;
}
