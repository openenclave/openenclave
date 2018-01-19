#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include "../args.h"

static OE_Mutex mutex = OE_MUTEX_INITIALIZER;

// Force parallel invocation of malloc():
static void _TestParallelMallocs()
{
    const size_t N = 100;
    void* ptrs[N];

    for (size_t i = 0; i < N; i++)
    {
        if (!(ptrs[i] = malloc(i + 1)))
            assert(0);
    }

    for (size_t i = 0; i < N; i++)
    {
        free(ptrs[i]);
    }
}

/* Check consistency of OE/pthread mutex static-initializer layout */
void TestMutexLayoutConsistency()
{
    assert(sizeof(OE_Mutex) == sizeof(pthread_mutex_t));
    static pthread_mutex_t m1 = PTHREAD_MUTEX_INITIALIZER;
    static OE_Mutex m2 = OE_MUTEX_INITIALIZER;
    assert(memcmp(&m1, &m2, sizeof(pthread_mutex_t)) == 0);
}

OE_ECALL void TestMutex(void* args_)
{
    TestMutexArgs* args = (TestMutexArgs*)args_;

    TestMutexLayoutConsistency();

    OE_MutexLock(&mutex);
    args->count++;
    OE_MutexUnlock(&mutex);

    OE_HostPrintf("Unlocked: %ld\n", OE_ThreadSelf());

}

static OE_Cond cond = OE_COND_INITIALIZER;
static OE_Mutex cond_mutex = OE_MUTEX_INITIALIZER;

OE_ECALL void Wait(void* args_)
{
    _TestParallelMallocs();

    /* Wait on the condition variable */
    OE_HostPrintf("Waiting: %ld\n", OE_ThreadSelf());

    OE_MutexLock(&cond_mutex);
    OE_CondWait(&cond, &cond_mutex);

    OE_HostPrintf("Done waiting!\n");

    _TestParallelMallocs();
}

OE_ECALL void Signal()
{
    OE_CondSignal(&cond);
}
