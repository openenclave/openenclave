#include <openenclave.h>

/* Set the spinlock value to 1 and return the old value */
static unsigned int _spin_set_locked(OE_Spinlock* spinlock)
{
    unsigned int oldValue;
    const unsigned int newValue = 1;

    asm volatile(
        "lock xchg %2, %1;"
        "mov %2, %0"
        : 
        "=m" (oldValue)  /* %0 */
        : 
        "m" (*spinlock), /* %1 */
        "r" (newValue)   /* %2 */
        : 
        "memory");

    return oldValue;
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
        *spinlock = OE_SPINLOCK_INITIALIZER;

    return 0;
}

int OE_SpinDestroy(OE_Spinlock* spinlock)
{
    return 0;
}
