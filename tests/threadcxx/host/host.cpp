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
#include "../args.h"

static TestMutexCxxArgs _args;

const size_t NUM_THREADS = 8;

void* Thread(void* args)
{
    oe_enclave_t* enclave = (oe_enclave_t*)args;

    oe_result_t result = oe_call_enclave(enclave, "TestMutexCxx", &_args);
    OE_TEST(result == OE_OK);

    return NULL;
}

void TestMutexCxx(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];
    _args.num_threads = NUM_THREADS;
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i] = std::thread(Thread, enclave);
    }

    for (size_t i = 0; i < NUM_THREADS; i++)
        threads[i].join();

    OE_TEST(_args.count1 == NUM_THREADS);
    OE_TEST(_args.count2 == NUM_THREADS);
}

void* WaiterThread(void* args)
{
    oe_enclave_t* enclave = (oe_enclave_t*)args;
    static WaitCxxArgs _args = {NUM_THREADS};

    oe_result_t result = oe_call_enclave(enclave, "WaitCxx", &_args);
    OE_TEST(result == OE_OK);

    return NULL;
}

void TestCondCxx(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];

    for (size_t i = 0; i < NUM_THREADS; i++)
        threads[i] = std::thread(WaiterThread, enclave);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    for (size_t i = 0; i < NUM_THREADS; i++)
        OE_TEST(oe_call_enclave(enclave, "SignalCxx", NULL) == OE_OK);

    for (size_t i = 0; i < NUM_THREADS; i++)
        threads[i].join();
}

void* CBTestWaiterThreadCxx(void* args)
{
    oe_enclave_t* enclave = (oe_enclave_t*)args;

    OE_TEST(
        oe_call_enclave(enclave, "CBTestWaiterThreadImplCxx", NULL) == OE_OK);

    return NULL;
}

void* CBTestSignalThreadCxx(void* args)
{
    oe_enclave_t* enclave = (oe_enclave_t*)args;

    OE_TEST(
        oe_call_enclave(enclave, "CBTestSignalThreadImplCxx", NULL) == OE_OK);

    return NULL;
}

void TestCondBroadcastCxx(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];
    std::thread signal_thread;

    printf("TestCondBroadcastCxx Starting\n");

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i] = std::thread(CBTestWaiterThreadCxx, enclave);
    }

    signal_thread = std::thread(CBTestSignalThreadCxx, enclave);

    for (size_t i = 0; i < NUM_THREADS; i++)
        threads[i].join();

    signal_thread.join();

    printf("TestCondBroadcastCxx Complete\n");
}

void* ExclusiveAccessThreadCxx(void* args)
{
    const size_t ITERS = 2;
    oe_enclave_t* enclave = (oe_enclave_t*)args;

    printf("Thread Starting\n");
    for (size_t i = 0; i < ITERS; i++)
    {
        OE_TEST(
            oe_call_enclave(enclave, "WaitForExclusiveAccessCxx", NULL) ==
            OE_OK);
        std::this_thread::sleep_for(std::chrono::microseconds(20 * 1000));

        OE_TEST(
            oe_call_enclave(enclave, "RelinquishExclusiveAccessCxx", NULL) ==
            OE_OK);
        std::this_thread::sleep_for(std::chrono::microseconds(20 * 1000));
    }
    printf("Thread Ending\n");
    return NULL;
}

void TestThreadWakeWaitCxx(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];

    printf("TestThreadWakeWaitCxx Starting\n");
    for (size_t i = 0; i < NUM_THREADS; i++)
        threads[i] = std::thread(ExclusiveAccessThreadCxx, enclave);

    for (size_t i = 0; i < NUM_THREADS; i++)
        threads[i].join();

    // The oe_calls in this test should succeed without any segv/double free.
    printf("TestThreadWakeWaitCxx Complete\n");
}

void* LockAndUnlockThread1Cxx(void* args)
{
    oe_enclave_t* enclave = (oe_enclave_t*)args;

    const size_t ITERS = 20000;

    for (size_t i = 0; i < ITERS; ++i)
    {
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexesCxx", (void*)"ABC") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexesCxx", (void*)"AB") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexesCxx", (void*)"AC") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexesCxx", (void*)"BC") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(
                enclave, "LockAndUnlockMutexesCxx", (void*)"ABBC") == OE_OK);
        OE_TEST(
            oe_call_enclave(
                enclave, "LockAndUnlockMutexesCxx", (void*)"ABAB") == OE_OK);
    }

    return NULL;
}

void* LockAndUnlockThread2Cxx(void* args)
{
    oe_enclave_t* enclave = (oe_enclave_t*)args;

    const size_t ITERS = 20000;

    for (size_t i = 0; i < ITERS; ++i)
    {
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexesCxx", (void*)"BC") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexesCxx", (void*)"ABC") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(
                enclave, "LockAndUnlockMutexesCxx", (void*)"BBCC") == OE_OK);
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexesCxx", (void*)"BBC") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(
                enclave, "LockAndUnlockMutexesCxx", (void*)"ABAB") == OE_OK);
        OE_TEST(
            oe_call_enclave(
                enclave, "LockAndUnlockMutexesCxx", (void*)"ABAC") == OE_OK);
        OE_TEST(
            oe_call_enclave(
                enclave, "LockAndUnlockMutexesCxx", (void*)"ABAB") == OE_OK);
    }

    return NULL;
}

// Launch multiple threads and try out various locking patterns on 3 mutexes.
// The locking patterns are chosen to not deadlock.
void TestThreadLockingPatternsCxx(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];

    printf("TestThreadLockingPatternsCxx Starting\n");
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i] = std::thread(
            (i & 1) ? LockAndUnlockThread2Cxx : LockAndUnlockThread1Cxx,
            enclave);
    }

    for (size_t i = 0; i < NUM_THREADS; i++)
        threads[i].join();

    // The oe_calls in this test should succeed without any OE_TEST() failures.
    printf("TestThreadLockingPatternsCxx Complete\n");
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

    if ((result = oe_create_enclave(
             argv[1],
             OE_ENCLAVE_TYPE_SGX,
             flags,
             NULL,
             0,
             NULL,
             0,
             &enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
    }

    TestMutexCxx(enclave);

    TestCondCxx(enclave);

    TestCondBroadcastCxx(enclave);

    TestThreadWakeWaitCxx(enclave);

    TestThreadLockingPatternsCxx(enclave);

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
