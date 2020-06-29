// Copyright (c) Open Enclave SDK contributors.
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
#include "threadcxx_t.h"

// Force parallel invocation of malloc():
static void _test_parallel_mallocs()
{
    const size_t N = 100;
    void* ptrs[N];

    for (size_t i = 0; i < N; i++)
    {
        if (!(ptrs[i] = malloc(i + 1)))
        {
            OE_TEST(0);
        }
    }

    for (size_t i = 0; i < N; i++)
    {
        free(ptrs[i]);
    }
}

void SpinLockAtomic(std::atomic_flag* lock)
{
    while (lock->test_and_set(std::memory_order_acquire)) // Acquire lock
    {
        continue; // spin
    }
}

void SpinUnlockAtomic(std::atomic_flag* lock)
{
    lock->clear(std::memory_order_release); // Release lock
}

static std::recursive_mutex recursive_mutex1;
static std::recursive_mutex recursive_mutex2;
static std::atomic<size_t> test_mutex_count1(0);
static std::atomic<size_t> test_mutex_count2(0);

void enc_test_mutex_cxx()
{
    std::stringstream ss;

    recursive_mutex1.lock();
    recursive_mutex1.lock();
    ++test_mutex_count1;
    recursive_mutex2.lock();
    recursive_mutex2.lock();
    ++test_mutex_count2;
    recursive_mutex1.unlock();
    recursive_mutex1.unlock();
    recursive_mutex2.unlock();
    recursive_mutex2.unlock();

    ss << "test_mutex_cxx:" << std::this_thread::get_id() << std::endl;
    std::cout << ss.str();
}

void enc_test_mutex_cxx_counts(size_t* count1, size_t* count2)
{
    *count1 = test_mutex_count1;
    *count2 = test_mutex_count2;
}

static std::mutex mutex1;
static std::mutex mutex2;
static std::condition_variable cond;
static std::mutex cond_mutex;

static void _test_mutex1_cxx(size_t* count)
{
    std::stringstream ss;

    mutex1.lock();
    (*count)++;
    mutex1.unlock();
    ss << "_test_mutex1_cxx:" << std::this_thread::get_id() << std::endl;
    std::cout << ss.str();
}

static void _test_mutex2_cxx(size_t* count)
{
    std::stringstream ss;

    mutex2.lock();
    (*count)++;
    mutex2.unlock();
    ss << "_test_mutex2_cxx:" << std::this_thread::get_id() << std::endl;
    std::cout << ss.str();
}

/* Assign a mutex to be used in test below: returns 1 or 2 */
static size_t _assign_mutex_cxx()
{
    static std::atomic<size_t> _n(0);
    size_t n = ++_n;
    return n % 2 + 1;
}

void enc_test_cond_cxx(size_t num_threads)
{
    static size_t _count1 = 0;
    static size_t _count2 = 0;
    std::stringstream ss;

    _test_parallel_mallocs();

    /* Assign the mutex to test */
    size_t n = _assign_mutex_cxx();

    if (n == 1)
    {
        _test_mutex1_cxx(&_count1);
    }
    else if (n == 2)
    {
        _test_mutex2_cxx(&_count2);
    }
    else
    {
        OE_TEST(0);
    }

    ss << "test_cond_cxx_thread:" << n << "()\n";
    std::cout << ss.str();

    /* Wait on the condition variable */
    ss << "Waiting: " << std::this_thread::get_id() << std::endl;
    std::cout << ss.str();

    {
        std::unique_lock<std::mutex> lock(cond_mutex);
        cond.wait(lock);

        std::cout << "Done waiting!\n";
    }

    OE_TEST(_count1 + _count2 == num_threads);

    _test_parallel_mallocs();
}

void enc_test_cond_cxx_signal()
{
    cond.notify_all();
}

static unsigned int nthreads = 0;
static std::mutex ex_mutex;
static std::condition_variable exclusive;

void enc_wait_for_exclusive_access_cxx()
{
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

void enc_relinquish_exclusive_access_cxx()
{
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

static std::recursive_mutex mutex_a;
static std::recursive_mutex mutex_b;
static std::recursive_mutex mutex_c;

static std::thread::id dummy_owner;
static std::thread::id a_owner;
static std::thread::id b_owner;
static std::thread::id c_owner;

static int a_locks = 0;
static int b_locks = 0;
static int c_locks = 0;

// Lock the specified mutexes in given order
// and unlock them in reverse order.
void enc_lock_and_unlock_mutexes_cxx(const char* mutexes)
{
    // Spinlock is used to modify the  _locked variables.
    static std::atomic_flag _lock = ATOMIC_FLAG_INIT;

    const char m = mutexes[0];

    std::recursive_mutex* mutex = nullptr;
    int* locks = nullptr;
    std::thread::id* owner = &dummy_owner;

    switch (m)
    {
        case 'A':
            mutex = &mutex_a;
            owner = &a_owner;
            locks = &a_locks;
            break;
        case 'B':
            mutex = &mutex_b;
            owner = &b_owner;
            locks = &b_locks;
            break;
        case 'C':
            mutex = &mutex_c;
            owner = &c_owner;
            locks = &c_locks;
            break;
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
            {
                OE_TEST(*owner == std::this_thread::get_id());
            }
            else
            {
                OE_TEST(*owner == dummy_owner);
            }

            *owner = std::this_thread::get_id();
            ++*locks;

            SpinUnlockAtomic(&_lock);
        }

        // Lock next specified mutex.
        enc_lock_and_unlock_mutexes_cxx(mutexes + 1);

        {
            // Test constraints
            SpinLockAtomic(&_lock);

            OE_TEST(*owner == std::this_thread::get_id());
            if (--*locks == 0)
            {
                *owner = dummy_owner;
            }

            SpinUnlockAtomic(&_lock);
        }

        mutex->unlock();
    }
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    128,  /* NumHeapPages */
    16,   /* NumStackPages */
    16);  /* NumTCS */
