// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>
#include "threadcxx_u.h"

const size_t NUM_THREADS = 8;

void test_mutex_cxx_thread(oe_enclave_t* enclave)
{
    OE_TEST(enc_test_mutex_cxx(enclave) == OE_OK);
}

void test_mutex_cxx(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i] = std::thread(test_mutex_cxx_thread, enclave);
    }

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i].join();
    }

    size_t count1 = 0;
    size_t count2 = 0;
    OE_TEST(enc_test_mutex_cxx_counts(enclave, &count1, &count2) == OE_OK);
    OE_TEST(count1 == NUM_THREADS);
    OE_TEST(count2 == NUM_THREADS);
}

void test_cond_cxx_thread(oe_enclave_t* enclave)
{
    OE_TEST(enc_test_cond_cxx(enclave, NUM_THREADS) == OE_OK);
}

void test_cond_cxx(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i] = std::thread(test_cond_cxx_thread, enclave);
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        OE_TEST(enc_test_cond_cxx_signal(enclave) == OE_OK);
    }

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i].join();
    }
}

void test_cb_cxx_waiter_thread(oe_enclave_t* enclave)
{
    OE_TEST(enc_test_cb_cxx_waiter(enclave) == OE_OK);
}

void test_cb_cxx_signal_thread(oe_enclave_t* enclave)
{
    OE_TEST(enc_test_cb_cxx_signal(enclave) == OE_OK);
}

void test_cond_broadcast_cxx(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];
    std::thread signal_thread;

    printf("test_cond_broadcast_cxx Starting\n");

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i] = std::thread(test_cb_cxx_waiter_thread, enclave);
    }

    signal_thread = std::thread(test_cb_cxx_signal_thread, enclave);

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i].join();
    }

    signal_thread.join();

    printf("test_cond_broadcast_cxx Complete\n");
}

void test_thread_wait_wake_cxx_worker(oe_enclave_t* enclave)
{
    const size_t ITERS = 2;

    printf("test_thread_wait_wait_cxx_worker Starting\n");
    for (size_t i = 0; i < ITERS; i++)
    {
        OE_TEST(enc_wait_for_exclusive_access_cxx(enclave) == OE_OK);
        std::this_thread::sleep_for(std::chrono::microseconds(20 * 1000));

        OE_TEST(enc_relinquish_exclusive_access_cxx(enclave) == OE_OK);
        std::this_thread::sleep_for(std::chrono::microseconds(20 * 1000));
    }
    printf("test_thread_wait_wait_cxx_worker Ending\n");
}

void test_thread_wake_wait_cxx(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];

    printf("test_thread_wake_wait_cxx Starting\n");
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i] = std::thread(test_thread_wait_wake_cxx_worker, enclave);
    }

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i].join();
    }

    // The oe_calls in this test should succeed without any segv/double free.
    printf("test_thread_wake_wait_cxx Complete\n");
}

void lock_and_unlock_cxx_thread1(oe_enclave_t* enclave)
{
    const size_t ITERS = 20000;

    for (size_t i = 0; i < ITERS; ++i)
    {
        OE_TEST(enc_lock_and_unlock_mutexes_cxx(enclave, "ABC") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes_cxx(enclave, "AB") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes_cxx(enclave, "AC") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes_cxx(enclave, "BC") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes_cxx(enclave, "ABBC") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes_cxx(enclave, "ABAB") == OE_OK);
    }
}

void lock_and_unlock_cxx_thread2(oe_enclave_t* enclave)
{
    const size_t ITERS = 20000;

    for (size_t i = 0; i < ITERS; ++i)
    {
        OE_TEST(enc_lock_and_unlock_mutexes_cxx(enclave, "BC") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes_cxx(enclave, "ABC") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes_cxx(enclave, "BBCC") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes_cxx(enclave, "ABAB") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes_cxx(enclave, "ABAC") == OE_OK);
        OE_TEST(enc_lock_and_unlock_mutexes_cxx(enclave, "ABAB") == OE_OK);
    }
}

// Launch multiple threads and try out various locking patterns on 3 mutexes.
// The locking patterns are chosen to not deadlock.
void test_thread_locking_patterns_cxx(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];

    printf("test_thread_locking_patterns_cxx Starting\n");
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i] = std::thread(
            (i & 1) ? lock_and_unlock_cxx_thread2 : lock_and_unlock_cxx_thread1,
            enclave);
    }

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i].join();
    }

    // The oe_calls in this test should succeed without any OE_TEST() failures.
    printf("test_thread_locking_patterns_cxx Complete\n");
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    result = oe_create_threadcxx_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        oe_put_err("oe_create_threadcxx_enclave(): result=%u", result);
    }

    test_mutex_cxx(enclave);

    test_cond_cxx(enclave);

    test_cond_broadcast_cxx(enclave);

    test_thread_wake_wait_cxx(enclave);

    test_thread_locking_patterns_cxx(enclave);

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
