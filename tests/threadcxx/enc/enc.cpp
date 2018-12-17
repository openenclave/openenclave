// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream> //std::cout
#include <mutex>
#include <sstream> //std::stringstream
#include <string>
#include <thread>
#include "../args.h"

static std::recursive_mutex recursive_mutex1;
static std::recursive_mutex recursive_mutex2;
static std::mutex mutex1;
static std::mutex mutex2;

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

void SpinLockAtomic(std::atomic_flag* lock)
{
    while (lock->test_and_set(std::memory_order_acquire)) // Acquire lock
        ;                                                 // spin
}

void SpinUnlockAtomic(std::atomic_flag* lock)
{
    lock->clear(std::memory_order_release); // Release lock
}

OE_ECALL void TestMutexCxx(void* args_)
{
    TestMutexCxxArgs* args = (TestMutexCxxArgs*)args_;
    std::stringstream ss;

    recursive_mutex1.lock();
    recursive_mutex1.lock();
    args->count1++;
    recursive_mutex2.lock();
    recursive_mutex2.lock();
    args->count2++;
    recursive_mutex1.unlock();
    recursive_mutex1.unlock();
    recursive_mutex2.unlock();
    recursive_mutex2.unlock();

    ss << "TestMutexCxx:" << std::this_thread::get_id() << std::endl;
    std::cout << ss.str();
}

static void _test_mutex1_cxx(size_t* count)
{
    std::stringstream ss;

    mutex1.lock();
    (*count)++;
    mutex1.unlock();
    ss << "TestMutex1Cxx:" << std::this_thread::get_id() << std::endl;
    std::cout << ss.str();
}

static void _test_mutex2_cxx(size_t* count)
{
    std::stringstream ss;

    mutex2.lock();
    (*count)++;
    mutex2.unlock();
    ss << "TestMutex2Cxx:" << std::this_thread::get_id() << std::endl;
    std::cout << ss.str();
}

static std::condition_variable cond;
static std::mutex cond_mutex;

/* Assign a mutex to be used in test below: returns 1 or 2 */
static size_t AssignMutexCxx()
{
    static size_t _n = 0;
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
    std::stringstream ss;

    _test_parallel_mallocs();

    /* Assign the mutex to test */
    size_t n = AssignMutexCxx();

    if (n == 1)
        _test_mutex1_cxx(&_count1);
    else if (n == 2)
        _test_mutex2_cxx(&_count2);
    else
        OE_TEST(0);

    ss << "TestMutex2Cxx" << n << "()\n";
    std::cout << ss.str();

    /* Wait on the condition variable */
    ss << "Waiting: " << std::this_thread::get_id() << std::endl;
    std::cout << ss.str();

    {
        std::unique_lock<std::mutex> lock(cond_mutex);
        cond.wait(lock);

        std::cout << "Done waiting!\n";
    }

    OE_TEST(_count1 + _count2 == args->num_threads);

    _test_parallel_mallocs();
}

OE_ECALL void SignalCxx()
{
    cond.notify_all();
}

static unsigned int nthreads = 0;
static std::mutex ex_mutex;
static std::condition_variable exclusive;

OE_ECALL void WaitForExclusiveAccessCxx(void* args_)
{
    OE_UNUSED(args_);

    std::stringstream ss;
    std::unique_lock<std::mutex> lock(ex_mutex);

    // Wait for other threads to finish
    while (nthreads > 0)
    {
        // Release mutex and wait for owning thread to finish
        ss << std::this_thread::get_id() << ": Waiting for exclusive access\n";
        std::cout << ss.str();
        exclusive.wait(lock);
    }

    ss << std::this_thread::get_id() << ": Obtained exclusive access\n";
    std::cout << ss.str();
    nthreads = 1;
}

OE_ECALL void RelinquishExclusiveAccessCxx(void* args_)
{
    OE_UNUSED(args_);

    std::stringstream ss;

    std::lock_guard<std::mutex> lg_lock(ex_mutex);

    // Mark thread as done
    nthreads = 0;

    // Signal waiting threads
    ss << std::this_thread::get_id() << ": Signalling waiting threads"
       << std::endl;
    std::cout << ss.str();
    exclusive.notify_all();

    ss << std::this_thread::get_id() << ": Relinquished exclusive access"
       << std::endl;
    std::cout << ss.str();
}

static std::mutex mutex_a;
static std::mutex mutex_b;
static std::mutex mutex_c;

static std::thread::id dummy_owner;
static std::thread::id a_owner;
static std::thread::id b_owner;
static std::thread::id c_owner;

static int a_locks = 0;
static int b_locks = 0;
static int c_locks = 0;

// Lock the specified mutexes in given order
// and unlock them in reverse order.
OE_ECALL void LockAndUnlockMutexesCxx(void* arg)
{
    // Spinlock is used to modify the  _locked variables.
    static std::atomic_flag _lock = ATOMIC_FLAG_INIT;

    char* mutexes = (char*)arg;
    const char m = mutexes[0];

    std::mutex* mutex = nullptr;
    int* locks = nullptr;
    std::thread::id* owner = &dummy_owner;

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

    if (mutex != nullptr)
    {
        // Lock mutex
        mutex->lock();
        {
            // Test constraints
            SpinLockAtomic(&_lock);

            // Recursive lock
            if (*locks > 0)
                OE_TEST(*owner == std::this_thread::get_id());
            else
                OE_TEST(*owner == dummy_owner);

            *owner = std::this_thread::get_id();
            ++*locks;

            SpinUnlockAtomic(&_lock);
        }

        // Lock next specified mutex.
        LockAndUnlockMutexesCxx(mutexes + 1);

        {
            // Test constraints
            SpinLockAtomic(&_lock);

            OE_TEST(*owner == std::this_thread::get_id());
            if (--*locks == 0)
                *owner = dummy_owner;

            SpinUnlockAtomic(&_lock);
        }

        mutex->unlock();
    }
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    128,  /* HeapPageCount */
    16,  /* StackPageCount */
    16);  /* TCSCount */

OE_DEFINE_EMPTY_ECALL_TABLE();
