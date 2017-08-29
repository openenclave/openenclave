#include <enc/enclave.h>
#include <enc/thread.h>

/*
**==============================================================================
**
** OE_Once()
**
**     Calls the function given by the parameter only once.
**
**==============================================================================
*/

OE_Result OE_Once(
    OE_OnceKey* key,
    void (*func)(void))
{
    if (!key || !func)
        return OE_INVALID_PARAMETER;

    /* Use doubled-checked locking technique to avoid subsequence locks */
    if (key->__initialized == 0)
    {
        OE_SpinLock(&key->__lock);

        if (key->__initialized == 0)
        {
            func();
            key->__initialized = 1;
        }

        OE_SpinUnlock(&key->__lock);
    }

    return OE_OK;
}
