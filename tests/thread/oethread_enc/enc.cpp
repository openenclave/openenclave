// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/thread.h>
#include <stdio.h>
#include <stdlib.h>
#include "../args.h"

static oe_mutex_t mutex1 = OE_MUTEX_INITIALIZER;
static oe_mutex_t mutex2 = OE_MUTEX_INITIALIZER;

// Force parallel invocation of malloc():
static void _test_parallel_mallocs()
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

    OE_TEST(oe_mutex_lock(&mutex1) == 0);
    OE_TEST(oe_mutex_lock(&mutex1) == 0);
    args->count1++;
    OE_TEST(oe_mutex_lock(&mutex2) == 0);
    OE_TEST(oe_mutex_lock(&mutex2) == 0);
    args->count2++;
    OE_TEST(oe_mutex_unlock(&mutex1) == 0);
    OE_TEST(oe_mutex_unlock(&mutex1) == 0);
    OE_TEST(oe_mutex_unlock(&mutex2) == 0);
    OE_TEST(oe_mutex_unlock(&mutex2) == 0);

    oe_host_printf("TestMutex: %lld\n", OE_LLU(oe_thread_self()));
}

static void _test_mutex1(size_t* count)
{
    OE_TEST(oe_mutex_lock(&mutex1) == 0);
    (*count)++;
    OE_TEST(oe_mutex_unlock(&mutex1) == 0);
    oe_host_printf("TestMutex1: %llu\n", OE_LLU(oe_thread_self()));
}

static void _test_mutex2(size_t* count)
{
    OE_TEST(oe_mutex_lock(&mutex2) == 0);
    (*count)++;
    OE_TEST(oe_mutex_unlock(&mutex2) == 0);
    oe_host_printf("TestMutex2: %llu\n", OE_LLU(oe_thread_self()));
}

static oe_cond_t cond = OE_COND_INITIALIZER;
static oe_mutex_t cond_mutex = OE_MUTEX_INITIALIZER;

/* Assign a mutex to be used in test below: returns 1 or 2 */
static size_t AssignMutex()
{
    static size_t _n = 0;
    static oe_spinlock_t _lock;

    oe_spin_lock(&_lock);
    _n++;
    oe_spin_unlock(&_lock);

    /* Return 0 or 1 */
    return (_n % 2) ? 1 : 2;
}

OE_ECALL void Wait(void* args_)
{
    static size_t _count1 = 0;
    static size_t _count2 = 0;
    WaitArgs* args = (WaitArgs*)args_;

    _test_parallel_mallocs();

    /* Assign the mutex to test */
    size_t n = AssignMutex();

    if (n == 1)
        _test_mutex1(&_count1);
    else if (n == 2)
        _test_mutex2(&_count2);
    else
        OE_TEST(0);

    oe_host_printf("TestMutex2%zu()\n", n);

    /* Wait on the condition variable */
    oe_host_printf("Waiting: %llu\n", OE_LLU(oe_thread_self()));

    oe_mutex_lock(&cond_mutex);
    oe_cond_wait(&cond, &cond_mutex);

    oe_host_printf("Done waiting!\n");

    oe_mutex_unlock(&cond_mutex);

    OE_TEST(_count1 + _count2 == args->num_threads);

    _test_parallel_mallocs();
}

OE_ECALL void Signal()
{
    oe_cond_signal(&cond);
}

static unsigned int nthreads = 0;

static oe_mutex_t ex_mutex = OE_MUTEX_INITIALIZER;

static oe_cond_t exclusive = OE_COND_INITIALIZER;

OE_ECALL void WaitForExclusiveAccess(void* args_)
{
    OE_UNUSED(args_);

    oe_mutex_lock(&ex_mutex);

    // Wait for other threads to finish
    while (nthreads > 0)
    {
        // Release mutex and wait for owning thread to finish
        oe_host_printf(
            "%llu: Waiting for exclusive access\n", OE_LLU(oe_thread_self()));
        oe_cond_wait(&exclusive, &ex_mutex);
    }

    oe_host_printf(
        "%llu: Obtained exclusive access\n", OE_LLU(oe_thread_self()));
    nthreads = 1;
    oe_mutex_unlock(&ex_mutex);
}

OE_ECALL void RelinquishExclusiveAccess(void* args_)
{
    OE_UNUSED(args_);

    oe_mutex_lock(&ex_mutex);

    // Mark thread as done
    nthreads = 0;

    // Signal waiting threads
    oe_host_printf(
        "%llu: Signalling waiting threads\n", OE_LLU(oe_thread_self()));
    oe_cond_signal(&exclusive);

    oe_host_printf(
        "%llu: Relinquished exlusive access\n", OE_LLU(oe_thread_self()));
    oe_mutex_unlock(&ex_mutex);
}

static oe_mutex_t mutex_a = OE_MUTEX_INITIALIZER;
static oe_mutex_t mutex_b = OE_MUTEX_INITIALIZER;
static oe_mutex_t mutex_c = OE_MUTEX_INITIALIZER;

static oe_thread_t a_owner = 0;
static oe_thread_t b_owner = 0;
static oe_thread_t c_owner = 0;

static int a_locks = 0;
static int b_locks = 0;
static int c_locks = 0;

// Lock the specified mutexes in given order
// and unlock them in reverse order.
OE_ECALL void LockAndUnlockMutexes(void* arg)
{
    // Spinlock is used to modify the  _locked variables.
    static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

    char* mutexes = (char*)arg;
    const char m = mutexes[0];

    oe_mutex_t* mutex = NULL;
    int* locks = NULL;
    oe_thread_t* owner = NULL;

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
        oe_mutex_lock(mutex);
        {
            // Test constraints
            oe_spin_lock(&_lock);

            // Recursive lock
            if (*locks > 0)
                OE_TEST(*owner == oe_thread_self());
            else
                OE_TEST(*owner == 0);

            *owner = oe_thread_self();
            ++*locks;

            oe_spin_unlock(&_lock);
        }

        // Lock next specified mutex.
        LockAndUnlockMutexes(mutexes + 1);

        {
            // Test constraints
            oe_spin_lock(&_lock);

            OE_TEST(*owner == oe_thread_self());
            if (--*locks == 0)
                *owner = 0;

            oe_spin_unlock(&_lock);
        }

        oe_mutex_unlock(mutex);
    }
}

// Keep the enclave busy until we get TCS exhaustion
OE_ECALL void TestTCSExhaustion(void* args_)
{
    TestTCSArgs* volatile args = (TestTCSArgs*)args_;
    static oe_spinlock_t _tcs_lock = OE_SPINLOCK_INITIALIZER;

    // Increment the number of threads only on getting the _tcs_lock
    oe_spin_lock(&_tcs_lock);
    args->num_tcs_used++;
    oe_spin_unlock(&_tcs_lock);
    // Wait until all the threads have returned from oe_call_enclave from
    // the host - these include those with unique TCSes and the ones
    // which failed.
    while (args->num_tcs_used + args->num_out_threads < args->tcs_req_count)
        ;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    128,  /* HeapPageCount */
    16,  /* StackPageCount */
    16);  /* TCSCount */

OE_DEFINE_EMPTY_ECALL_TABLE();
