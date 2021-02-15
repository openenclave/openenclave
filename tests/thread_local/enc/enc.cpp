

// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <random>
#include <set>
#include <thread>

#include "thread_local_t.h"
#include "visibility.h"

// These variables will be put in .tdata
VISIBILITY_SPEC __thread volatile int __thread_int = 1;
VISIBILITY_SPEC __thread volatile int g_x[10] = {8};

struct thread_local_struct
{
    bool initialized;
    int value;

    thread_local_struct(int v)
    {
        value = v;
        initialized = true;
        printf("thread_local_struct initialized with value = %d\n", value);
    }
    ~thread_local_struct()
    {
        printf("thread_local_struct destructed, value = %d\n", value);
    }
};

// These variables will be put in .tbss
// Dynamic thread specific destructors for g_s and dist.
VISIBILITY_SPEC extern thread_local std::random_device g_rd;
VISIBILITY_SPEC extern thread_local std::mt19937 g_mt;
VISIBILITY_SPEC extern thread_local std::uniform_real_distribution<double>
    g_dist;
VISIBILITY_SPEC thread_local volatile thread_local_struct g_s(
    static_cast<int>(g_dist(g_mt)));

// This variable will be put in .tdata
VISIBILITY_SPEC thread_local int thread_local_int = 5;

// Helper function for debugging.
// Gets the value of the FS segment.
void* get_fs()
{
    void* fs = NULL;
    asm volatile("movq %%fs:0, %0" : "=r"(fs));
    return fs;
}

// Helper class for spinlocks
class spinlock
{
    std::atomic_flag locked = ATOMIC_FLAG_INIT;

  public:
    void acquire()
    {
        while (locked.test_and_set(std::memory_order_acquire))
            ;
    }

    void release()
    {
        locked.clear(std::memory_order_release);
    }
};

// Assert that each thread-local variable has a unique address across threads.
std::set<volatile void*> g_addresses;
spinlock g_lock;

// Total number of threads.
volatile int g_total_num_threads = 0;

// Current number of threads.
volatile int g_num_threads = 0;

void assert_unique_address(volatile void* var_address)
{
    g_lock.acquire();
    OE_TEST(g_addresses.count(var_address) == 0);
    g_addresses.insert(var_address);
    g_lock.release();
}

// Clear test data
void prepare_for_test(int total_num_threads)
{
    g_lock.acquire();
    g_addresses.clear();
    g_total_num_threads = total_num_threads;
    g_num_threads = 0;
    g_lock.release();
}

void increment_num_threads()
{
    g_lock.acquire();
    OE_TEST(++g_num_threads <= g_total_num_threads);
    g_lock.release();
}

void wait_for_test_completion()
{
    // Wait for all threads to complete
    bool complete = false;
    while (!complete)
    {
        // Sleep for sometime.
        host_usleep(10);

        g_lock.acquire();
        complete = (g_num_threads == g_total_num_threads);
        g_lock.release();
    }
}

// Run an enclave thread and perform various assertions.
void enclave_thread(int thread_num, int iters, int step)
{
    increment_num_threads();

    // Assert that each thread-local variable has a unique address.
    assert_unique_address(&g_s);
    assert_unique_address(&g_dist);
    assert_unique_address(&g_mt);
    assert_unique_address(&g_rd);
    assert_unique_address(&thread_local_int);
    assert_unique_address(&g_x);
    assert_unique_address(&__thread_int);

    // Test that the complex thread-local variable has been initialized.
    OE_TEST(g_s.initialized);
    g_s.value += thread_num;

    // Test that the thread local variables have expected value.
    volatile int thread_local_value1 = __thread_int;
    volatile int thread_local_value2 = thread_local_int;

    OE_TEST(thread_local_value1 == 1);
    OE_TEST(thread_local_value2 == 5);

    int start_value1 = thread_local_value1;
    int start_value2 = thread_local_value2;

    // Iterate specified number of times and increment values by step.
    // Test that after sleeping for a bit, the values are consistent.
    for (int i = 0; i < iters; i++)
    {
        OE_TEST(thread_local_value1 == __thread_int);
        OE_TEST(thread_local_value2 == thread_local_int);

        thread_local_value1 += step;
        thread_local_value2 += step;

        __thread_int = thread_local_value1;
        thread_local_int = thread_local_value2;

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        g_x[i % 10]++;
    }

    // Use a formula to assert the final values of variables.
    int total = __thread_int + thread_local_int;
    OE_TEST(total == (2 * step * iters) + start_value1 + start_value2);

    wait_for_test_completion();
}

#define NUM_TCS 16

OE_SET_ENCLAVE_SGX(
    0,                                  /* ProductID */
    0,                                  /* SecurityVersion */
    true,                               /* Debug */
    OE_TEST_MT_HEAP_SIZE(NUM_TCS) + 64, /* NumHeapPages */
    16,                                 /* NumStackPages */
    NUM_TCS);                           /* NumTCS */
