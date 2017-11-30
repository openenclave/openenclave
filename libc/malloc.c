#include <openenclave/enclave.h>
#include <openenclave/bits/sgxtypes.h>

static void __wait(
    volatile int *addr, 
    volatile int *waiters, 
    int val, 
    int priv);

static void __wake(
    volatile void *addr, 
    int cnt, 
    int priv);

#define _PTHREAD_IMPL_H
#include "../3rdparty/musl/musl/src/malloc/malloc.c"

static void __wait(
    volatile int *addr, 
    volatile int *waiters, 
    int val, /* will be 1 */
    int priv)
{
    int spins = 100;
    OE_ThreadData* self = OE_GetThreadData();

    while (spins-- && (!waiters || !*waiters)) 
    {
        if (*addr == val) 
            a_spin();
        else 
            return;
    }

    if (waiters) 
        a_inc(waiters);

    while (*addr == val) 
    {
        OE_ThreadWait(self);
    }

    if (waiters) 
        a_dec(waiters);
}

static void __wake(
    volatile void *addr, 
    int cnt, /* will be 1 */
    int priv) /* ignored */
{
    OE_ThreadWait(OE_GetThreadData());
}

