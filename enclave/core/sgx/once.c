// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdio.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/utils.h>

oe_result_t oe_once(oe_once_t* once, void (*func)(void))
{
    if (!once)
        return OE_INVALID_PARAMETER;

    /* Double checked locking (DCLP). */
    oe_once_t o = *once;

    /* DCLP Acquire barrier. */
    OE_ATOMIC_MEMORY_BARRIER_ACQUIRE();
    if (o == 0)
    {
        static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

        oe_spin_lock(&_lock);

        if (*once == 0)
        {
            if (func)
                func();

            /* DCLP Release barrier. */
            OE_ATOMIC_MEMORY_BARRIER_RELEASE();
            *once = 1;
        }

        oe_spin_unlock(&_lock);
    }

    return OE_OK;
}
