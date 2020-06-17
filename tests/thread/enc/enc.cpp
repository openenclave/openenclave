// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef _PTHREAD_ENC_
#include "thread.h"
#endif

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <atomic>
#include "thread_t.h"

static oe_mutex_t mutex1 = OE_MUTEX_INITIALIZER;
static oe_mutex_t mutex2 = OE_MUTEX_INITIALIZER;
static size_t test_mutex_count1 = 0;
static size_t test_mutex_count2 = 0;

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

void enc_test_mutex()
{
    OE_TEST(oe_mutex_lock(&mutex1) == 0);
    OE_TEST(oe_mutex_lock(&mutex1) == 0);
    ++test_mutex_count1;
    OE_TEST(oe_mutex_lock(&mutex2) == 0);
    OE_TEST(oe_mutex_lock(&mutex2) == 0);
    ++test_mutex_count2;
    OE_TEST(oe_mutex_unlock(&mutex1) == 0);
    OE_TEST(oe_mutex_unlock(&mutex1) == 0);
    OE_TEST(oe_mutex_unlock(&mutex2) == 0);
    OE_TEST(oe_mutex_unlock(&mutex2) == 0);

    oe_host_printf("enc_test_mutex: %lld\n", OE_LLU(oe_thread_self()));
}

static void _test_mutex1(size_t* count)
{
    OE_TEST(oe_mutex_lock(&mutex1) == 0);
    (*count)++;
    OE_TEST(oe_mutex_unlock(&mutex1) == 0);
    oe_host_printf("_test_mutex1: %llu\n", OE_LLU(oe_thread_self()));
}

static void _test_mutex2(size_t* count)
{
    OE_TEST(oe_mutex_lock(&mutex2) == 0);
    (*count)++;
    OE_TEST(oe_mutex_unlock(&mutex2) == 0);
    oe_host_printf("_tes_mutex2: %llu\n", OE_LLU(oe_thread_self()));
}

void enc_test_mutex_counts(size_t* count1, size_t* count2)
{
    OE_TEST(oe_mutex_lock(&mutex1) == 0);
    *count1 = test_mutex_count1;
    OE_TEST(oe_mutex_unlock(&mutex1) == 0);
    OE_TEST(oe_mutex_lock(&mutex2) == 0);
    *count2 = test_mutex_count2;
    OE_TEST(oe_mutex_unlock(&mutex2) == 0);
}

static oe_cond_t cond = OE_COND_INITIALIZER;
static oe_mutex_t cond_mutex = OE_MUTEX_INITIALIZER;

/* Assign a mutex to be used in test below: returns 1 or 2 */
static size_t assign_mutex()
{
    static size_t _n = 0;
    static oe_spinlock_t _lock;

    oe_spin_lock(&_lock);
    _n++;
    oe_spin_unlock(&_lock);

    /* Return 0 or 1 */
    return (_n % 2) ? 1 : 2;
}

void enc_wait(size_t num_threads)
{
    static size_t _count1 = 0;
    static size_t _count2 = 0;

    _test_parallel_mallocs();

    /* Assign the mutex to test */
    size_t n = assign_mutex();

    if (n == 1)
    {
        _test_mutex1(&_count1);
    }
    else if (n == 2)
    {
        _test_mutex2(&_count2);
    }
    else
    {
        OE_TEST(0);
    }

    oe_host_printf("TestMutex2%zu()\n", n);

    /* Wait on the condition variable */
    oe_host_printf("Waiting: %llu\n", OE_LLU(oe_thread_self()));

    oe_mutex_lock(&cond_mutex);
    oe_cond_wait(&cond, &cond_mutex);

    oe_host_printf("Done waiting!\n");

    oe_mutex_unlock(&cond_mutex);

    OE_TEST(_count1 + _count2 == num_threads);

    _test_parallel_mallocs();
}

void enc_signal()
{
    oe_cond_signal(&cond);
}

static unsigned int nthreads = 0;

static oe_mutex_t ex_mutex = OE_MUTEX_INITIALIZER;

static oe_cond_t exclusive = OE_COND_INITIALIZER;

void enc_wait_for_exclusive_access()
{
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

void enc_relinquish_exclusive_access()
{
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
void enc_lock_and_unlock_mutexes(const char* mutex_ids)
{
    // Spinlock is used to modify the  _locked variables.
    static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

    oe_mutex_t* mutex = NULL;
    int* locks = NULL;
    oe_thread_t* owner = NULL;

    switch (mutex_ids[0])
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
    };

    if (mutex != NULL)
    {
        // Lock mutex
        oe_mutex_lock(mutex);
        {
            // Test constraints
            oe_spin_lock(&_lock);

            // Recursive lock
            if (*locks > 0)
            {
                OE_TEST(*owner == oe_thread_self());
            }
            else
            {
                OE_TEST(*owner == 0);
            }

            *owner = oe_thread_self();
            ++*locks;

            oe_spin_unlock(&_lock);
        }

        // Lock next specified mutex.
        enc_lock_and_unlock_mutexes(mutex_ids + 1);

        {
            // Test constraints
            oe_spin_lock(&_lock);

            OE_TEST(*owner == oe_thread_self());
            if (--*locks == 0)
            {
                *owner = 0;
            }

            oe_spin_unlock(&_lock);
        }

        oe_mutex_unlock(mutex);
    }
}

// test_tcs_exhaustion
static std::atomic<size_t> g_tcs_used_thread_count(0);

// this ecall increments a counter (tcs_used_thread_count)
void enc_test_tcs_exhaustion()
{
    ++g_tcs_used_thread_count;

    // Wait in the host until desired tcs exhaustion has been reached.
    OE_TEST(host_wait() == OE_OK);
}

size_t enc_tcs_used_thread_count()
{
    return g_tcs_used_thread_count;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    128,  /* NumHeapPages */
    16,   /* NumStackPages */
    16);  /* NumTCS */
