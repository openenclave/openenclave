#include <openenclave/enclave.h>
#include <stdio.h>
#include "../args.h"

static OE_Mutex mutex = OE_MUTEX_INITIALIZER;

OE_ECALL void TestMutex(void* args_)
{
    TestMutexArgs* args = (TestMutexArgs*)args_;

    OE_MutexLock(&mutex);
    args->count++;
    OE_MutexUnlock(&mutex);

    OE_HostPrintf("Unlocked: %ld\n", OE_ThreadSelf());
}

static OE_Cond cond = OE_COND_INITIALIZER;
static OE_Mutex cond_mutex = OE_MUTEX_INITIALIZER;

OE_ECALL void Wait(void* args_)
{
    /* Wait on the condition variable */
    OE_HostPrintf("Waiting: %ld\n", OE_ThreadSelf());

    OE_MutexLock(&cond_mutex);
    OE_CondWait(&cond, &cond_mutex);

    OE_HostPrintf("Done waiting!\n");
}

OE_ECALL void Signal()
{
    OE_CondSignal(&cond);
}
