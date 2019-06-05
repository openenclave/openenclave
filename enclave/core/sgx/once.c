// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/utils.h>

#define SPINLOCK_NOT_USED 0
#define SPINLOCK_ACTIVELY_HELD 1
#define SPINLOCK_USED 2

oe_result_t oe_once(oe_once_t* once, void (*func)(void))
{
    if (!once)
        return OE_INVALID_PARAMETER;

    /* Double checked locking (DCLP). */
    /* DCLP Acquire barrier. */
    OE_ATOMIC_MEMORY_BARRIER_ACQUIRE();
    if (*once != SPINLOCK_USED)
    {
        oe_once_t retval = __sync_val_compare_and_swap(
            once, SPINLOCK_NOT_USED, SPINLOCK_ACTIVELY_HELD);
        if (retval == SPINLOCK_NOT_USED)
        {
            if (func)
                func();

            *once = SPINLOCK_USED;
        }
        else if (retval == SPINLOCK_ACTIVELY_HELD)
        {
            while (__sync_val_compare_and_swap(
                       once, SPINLOCK_ACTIVELY_HELD, SPINLOCK_ACTIVELY_HELD) !=
                   SPINLOCK_ACTIVELY_HELD)
            {
                asm volatile("pause");
            }
        }
    }
    OE_ATOMIC_MEMORY_BARRIER_RELEASE();
    return OE_OK;
}
