// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#include <openenclave/internal/thread.h>
#else
#include <openenclave/host.h>
#endif

/* Set the spinlock value to 1 and return the old value */
static unsigned int _spin_set_locked(oe_spinlock_t* spinlock)
{
    unsigned int value = 1;

    asm volatile("lock xchg %0, %1;"
                 : "=r"(value)     /* %0 */
                 : "m"(*spinlock), /* %1 */
                   "0"(value)      /* also %2 */
                 : "memory");

    return value;
}

oe_result_t oe_spin_init(oe_spinlock_t* spinlock)
{
    if (!spinlock)
        return OE_INVALID_PARAMETER;

    *spinlock = OE_SPINLOCK_INITIALIZER;

    return OE_OK;
}

oe_result_t oe_spin_lock(oe_spinlock_t* spinlock)
{
    if (!spinlock)
        return OE_INVALID_PARAMETER;

    while (_spin_set_locked((volatile unsigned int*)spinlock) != 0)
    {
        /* Spin while waiting for spinlock to be released (become 1) */
        while (*spinlock)
        {
            /* Yield to CPU */
            asm volatile("pause");
        }
    }

    return OE_OK;
}

oe_result_t oe_spin_unlock(oe_spinlock_t* spinlock)
{
    if (!spinlock)
        return OE_INVALID_PARAMETER;

    asm volatile("movl %0, %1;"
                 :
                 : "r"(OE_SPINLOCK_INITIALIZER), "m"(*spinlock) /* %1 */
                 : "memory");

    return OE_OK;
}

oe_result_t oe_spin_destroy(oe_spinlock_t* spinlock)
{
    if (!spinlock)
        return OE_INVALID_PARAMETER;

    return OE_OK;
}
