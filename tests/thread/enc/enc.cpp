// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/tests.h>
#include <openenclave/enclave.h>
#include "../args.h"

static OE_Mutex mutex1 = OE_MUTEX_INITIALIZER;
static OE_Mutex mutex2 = OE_MUTEX_INITIALIZER;

// Force parallel invocation of malloc():
static void _TestParallelMallocs()
{
    const size_t N = 100;
    void* ptrs[N];

    for (size_t i = 0; i < N; i++)
    {
        if (!(ptrs[i] = malloc(i + 1)))
            OE_TEST(0);
    }

    for (size_t i = 0; i < N; i++)
    {
        free(ptrs[i]);
    }
}

OE_ECALL void TestMutex(void* args_)
{
    TestMutexArgs* args = (TestMutexArgs*)args_;

    OE_TEST(OE_MutexLock(&mutex1) == 0);
    OE_TEST(OE_MutexLock(&mutex1) == 0);
    args->count1++;
    OE_TEST(OE_MutexLock(&mutex2) == 0);
    OE_TEST(OE_MutexLock(&mutex2) == 0);
    args->count2++;
    OE_TEST(OE_MutexUnlock(&mutex1) == 0);
    OE_TEST(OE_MutexUnlock(&mutex1) == 0);
    OE_TEST(OE_MutexUnlock(&mutex2) == 0);
    OE_TEST(OE_MutexUnlock(&mutex2) == 0);

    OE_HostPrintf("TestMutex: %ld\n", OE_ThreadSelf());
}

static void _TestMutex1(size_t* count)
{
    OE_TEST(OE_MutexLock(&mutex1) == 0);
    (*count)++;
    OE_TEST(OE_MutexUnlock(&mutex1) == 0);
    OE_HostPrintf("TestMutex1: %ld\n", OE_ThreadSelf());
}

static void _TestMutex2(size_t* count)
{
    OE_TEST(OE_MutexLock(&mutex2) == 0);
    (*count)++;
    OE_TEST(OE_MutexUnlock(&mutex2) == 0);
    OE_HostPrintf("TestMutex2: %ld\n", OE_ThreadSelf());
}

static OE_Cond cond = OE_COND_INITIALIZER;
static OE_Mutex cond_mutex = OE_MUTEX_INITIALIZER;

/* Assign a mutex to be used in test below: returns 1 or 2 */
static size_t AssignMutex()
{
    static size_t _n = 0;
    static OE_Spinlock _lock;

    OE_SpinLock(&_lock);
    _n++;
    OE_SpinUnlock(&_lock);

    /* Return 0 or 1 */
    return (_n % 2) ? 1 : 2;
}

OE_ECALL void Wait(void* args_)
{
    static size_t _count1 = 0;
    static size_t _count2 = 0;
    WaitArgs* args = (WaitArgs*)args_;

    _TestParallelMallocs();

    /* Assign the mutex to test */
    size_t n = AssignMutex();

    if (n == 1)
        _TestMutex1(&_count1);
    else if (n == 2)
        _TestMutex2(&_count2);
    else
        OE_TEST(0);

    OE_HostPrintf("TestMutex2%zu()\n", n);

    /* Wait on the condition variable */
    OE_HostPrintf("Waiting: %ld\n", OE_ThreadSelf());

    OE_MutexLock(&cond_mutex);
    OE_CondWait(&cond, &cond_mutex);

    OE_HostPrintf("Done waiting!\n");

    OE_MutexUnlock(&cond_mutex);

    OE_TEST(_count1 + _count2 == args->numThreads);

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

static OE_Mutex mutex_a = OE_MUTEX_INITIALIZER;
static OE_Mutex mutex_b = OE_MUTEX_INITIALIZER;
static OE_Mutex mutex_c = OE_MUTEX_INITIALIZER;

static OE_Thread a_owner = 0;
static OE_Thread b_owner = 0;
static OE_Thread c_owner = 0;

static int a_locks = 0;
static int b_locks = 0;
static int c_locks = 0;

// Lock the specified mutexes in given order
// and unlock them in reverse order.
OE_ECALL void LockAndUnlockMutexes(void* arg)
{
    // Spinlock is used to modify the  _locked variables.
    static OE_Spinlock _lock = OE_SPINLOCK_INITIALIZER;

    char* mutexes = (char*)arg;
    const char m = mutexes[0];

    OE_Mutex* mutex = NULL;
    int* locks = NULL;
    OE_Thread* owner = NULL;

    if (m == 'A')
    {
        mutex = &mutex_a;
        owner = &a_owner;
        locks = &a_locks;
    }
    else if (m == 'B')
    {
        mutex = &mutex_b;
        owner = &b_owner;
        locks = &b_locks;
    }
    else if (m == 'C')
    {
        mutex = &mutex_c;
        owner = &c_owner;
        locks = &c_locks;
    }

    if (mutex != NULL)
    {
        // Lock mutex
        OE_MutexLock(mutex);
        {
            // Test constraints
            OE_SpinLock(&_lock);

            // Recursive lock
            if (*locks > 0)
                OE_TEST(*owner == OE_ThreadSelf());
            else
                OE_TEST(*owner == 0);

            *owner = OE_ThreadSelf();
            ++*locks;

            OE_SpinUnlock(&_lock);
        }

        // Lock next specified mutex.
        LockAndUnlockMutexes(mutexes + 1);

        {
            // Test constraints
            OE_SpinLock(&_lock);

            OE_TEST(*owner == OE_ThreadSelf());
            if (--*locks == 0)
                *owner = 0;

            OE_SpinUnlock(&_lock);
        }

        OE_MutexUnlock(mutex);
    }
}
