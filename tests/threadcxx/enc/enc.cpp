// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <iostream> //TODO - Remove this later
#include <stdlib.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include "../args.h"

static std::mutex mtx; //mutex1 = OE_MUTEX_INITIALIZER;
static std::mutex mutex1; //mutex1 = OE_MUTEX_INITIALIZER;
static std::mutex mutex2; //mutex1 = OE_MUTEX_INITIALIZER;

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

void SpinLockAtomic(std::atomic_flag *lock)
{
  while (lock->test_and_set(std::memory_order_acquire)) // Acquire lock
    ; //spin

}

void SpinUnlockAtomic(std::atomic_flag *lock)
{
  lock->clear(std::memory_order_release); // Release lock
}

OE_ECALL void TestMutexCxx(void* args_)
{
    TestMutexCxxArgs* args = (TestMutexCxxArgs*)args_;

    mtx.lock();
    args->ID++;
    mtx.lock();

    //The output should not come out garbled as each thread is holding the lock
    for (size_t i=0; i<10; ++i)
    {
      oe_host_printf("%d", (int)args->ID);
    } 
    std::cout << " " << std::this_thread::get_id();
    oe_host_printf("\n");
    args->count++;
    mtx.unlock();
    mtx.unlock();

    //TODO - oe_host_printf("TestMutex: %lld\n", OE_LLU(oe_thread_self()));
}

static void _TestMutex1Cxx(size_t* count)
{
    mutex1.lock();
    (*count)++;
    mutex1.unlock();

    //TODO - oe_host_printf("TestMutex1Cxx: %llu\n", OE_LLU(oe_thread_self()));
}

static void _TestMutex2Cxx(size_t* count)
{
    mutex2.lock();
    (*count)++;
    mutex2.unlock();
    //TODO - oe_host_printf("TestMutex2Cxx: %llu\n", OE_LLU(oe_thread_self()));
}

static std::condition_variable_any cond; // = OE_COND_INITIALIZER;
static std::mutex cond_mutex; // = OE_MUTEX_INITIALIZER;

/* Assign a mutex to be used in test below: returns 1 or 2 */
static size_t AssignMutexCxx()
{
    static size_t _n = 0;
    //static oe_spinlock_t _lock;
    static std::atomic_flag _lock = ATOMIC_FLAG_INIT;
    
    SpinLockAtomic(&_lock);
    _n++;
    SpinUnlockAtomic(&_lock);

    /* Return 0 or 1 */
    return (_n % 2) ? 1 : 2;
}



OE_ECALL void WaitCxx(void* args_)
{
    static size_t _count1 = 0;
    static size_t _count2 = 0;
    WaitCxxArgs* args = (WaitCxxArgs*)args_;

    _TestParallelMallocs();

    /* Assign the mutex to test */
    size_t n = AssignMutexCxx();

    if (n == 1)
        _TestMutex1Cxx(&_count1);
    else if (n == 2)
        _TestMutex2Cxx(&_count2);
    else
        OE_TEST(0);

    oe_host_printf("TestMutex2Cxx%zu()\n", n);

    /* Wait on the condition variable */
    //TODO - oe_host_printf("Waiting: %llu\n", OE_LLU(oe_thread_self()));

    cond_mutex.lock();
    cond.wait(cond_mutex); 

    oe_host_printf("Done waiting!\n");

    cond_mutex.unlock();

    OE_TEST(_count1 + _count2 == args->numThreads);

    _TestParallelMallocs();
}

OE_ECALL void SignalCxx()
{
    cond.notify_all();
}
