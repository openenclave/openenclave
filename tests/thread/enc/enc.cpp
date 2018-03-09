// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>
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

static unsigned int nthreads = 0;

static OE_Mutex ex_mutex = OE_MUTEX_INITIALIZER;

static OE_Cond exclusive = OE_COND_INITIALIZER;

OE_ECALL void WaitForExclusiveAccess(void* args_)
{
    OE_MutexLock(&ex_mutex);

    // Wait for other threads to finish
    while (nthreads > 0)
    {
        // Release mutex and wait for owning thread to finish
        OE_HostPrintf("%ld: Waiting for exclusive access\n", OE_ThreadSelf());
        OE_CondWait(&exclusive, &ex_mutex);
    }

    OE_HostPrintf("%ld: Obtained exclusive access\n", OE_ThreadSelf());
    nthreads = 1;
    OE_MutexUnlock(&ex_mutex);
}

OE_ECALL void RelinquishExclusiveAccess(void* args_)
{
    OE_MutexLock(&ex_mutex);

    // Mark thread as done
    nthreads = 0;

    // Signal waiting threads
    OE_HostPrintf("%ld: Signalling waiting threads\n", OE_ThreadSelf());
    OE_CondSignal(&exclusive);

    OE_HostPrintf("%ld: Relinquished exlusive access\n", OE_ThreadSelf());
    OE_MutexUnlock(&ex_mutex);
}
