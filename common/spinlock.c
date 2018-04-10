// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#else
#include <openenclave/host.h>
#endif

/* Set the spinlock value to 1 and return the old value */
static unsigned int _spin_set_locked(OE_Spinlock* spinlock)
{
    unsigned int value = 1;

    asm volatile(
        "lock xchg %0, %1;"
        : "=r"(value)     /* %0 */
        : "m"(*spinlock), /* %1 */
          "0"(value)      /* also %2 */
        : "memory");

    return value;
}

int OE_SpinInit(OE_Spinlock* spinlock)
{
    if (spinlock)
        *spinlock = OE_SPINLOCK_INITIALIZER;

    return 0;
}

int OE_SpinLock(OE_Spinlock* spinlock)
{
    if (spinlock)
    {
        while (_spin_set_locked((volatile unsigned int*)spinlock) != 0)
        {
            /* Spin while waiting for spinlock to be released (become 1) */
            while (*spinlock)
            {
                /* Yield to CPU */
                asm volatile("pause");
            }
        }
    }

    return 0;
}

int OE_SpinUnlock(OE_Spinlock* spinlock)
{
    if (spinlock)
    {
        asm volatile(
            "movl %0, %1;"
            :
            : "r"(OE_SPINLOCK_INITIALIZER), "m"(*spinlock) /* %1 */
            : "memory");
    }

    return 0;
}

int OE_SpinDestroy(OE_Spinlock* spinlock)
{
    return 0;
}
