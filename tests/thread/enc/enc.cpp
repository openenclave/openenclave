#include <stdio.h>
#include <openenclave.h>
#include "../args.h"

static OE_Mutex mutex = OE_MUTEX_INITIALIZER;

OE_ECALL void TestMutex(void* args_)
{
    TestMutexArgs* args = (TestMutexArgs*)args_;
    char buf[128];

    OE_MutexLock(&mutex);
    args->count++;
    OE_MutexUnlock(&mutex);

    snprintf(buf, sizeof(buf), "Unlocked: %ld", OE_ThreadSelf());
    puts_u(buf);

}

static OE_Cond cond = OE_COND_INITIALIZER;
static OE_Mutex cond_mutex = OE_MUTEX_INITIALIZER;

OE_ECALL void Wait(void* args_)
{
    /* Wait on the condition variable */
    char buf[128];
    snprintf(buf, sizeof(buf), "Waiting: %ld", OE_ThreadSelf());
    puts_u(buf);

    OE_MutexLock(&cond_mutex);
    OE_CondWait(&cond, &cond_mutex);

    puts_u("Done waiting!");
}

OE_ECALL void Signal()
{
    OE_CondSignal(&cond);
}
