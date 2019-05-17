// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/posix/lock.h>

oe_result_t oe_conditional_lock(oe_spinlock_t* lock, bool* locked)
{
    oe_result_t result = OE_UNEXPECTED;

    if (locked)
    {
        if (!*locked)
        {
            OE_CHECK(oe_spin_lock(lock));
            *locked = true;
        }
    }
    else
    {
        OE_CHECK(oe_spin_lock(lock));
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_conditional_unlock(oe_spinlock_t* lock, bool* locked)
{
    oe_result_t result = OE_UNEXPECTED;

    if (locked)
    {
        if (*locked)
        {
            OE_CHECK(oe_spin_unlock(lock));
            *locked = false;
        }
    }
    else
    {
        OE_CHECK(oe_spin_unlock(lock));
    }

    result = OE_OK;

done:
    return result;
}
