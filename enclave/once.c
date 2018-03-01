#include <openenclave/enclave.h>

int OE_Once(OE_OnceType* once, void (*func)(void))
{
    if (!once)
        return -1;

    /* Use doubled-checked locking technique to avoid subsequence locks */
    if (*once == 0)
    {
        static OE_Spinlock _lock = OE_SPINLOCK_INITIALIZER;

        OE_SpinLock(&_lock);

        if (*once == 0)
        {
            if (func)
                func();
            *once = 1;
        }

        OE_SpinUnlock(&_lock);
    }

    return 0;
}
