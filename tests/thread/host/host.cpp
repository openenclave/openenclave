// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include "../args.h"

static TestMutexArgs _args;

const size_t NUM_THREADS = 8;

void* Thread(void* args)
{
    oe_enclave_t* enclave = (oe_enclave_t*)args;

    oe_result_t result = oe_call_enclave(enclave, "TestMutex", &_args);
    OE_TEST(result == OE_OK);

    return NULL;
}

void TestMutex(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];

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
    static WaitArgs _args = {NUM_THREADS};

    oe_result_t result = oe_call_enclave(enclave, "Wait", &_args);
    OE_TEST(result == OE_OK);

    return NULL;
}

void TestCond(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];

    for (size_t i = 0; i < NUM_THREADS; i++)
        threads[i] = std::thread(WaiterThread, enclave);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    for (size_t i = 0; i < NUM_THREADS; i++)
        OE_TEST(oe_call_enclave(enclave, "Signal", NULL) == OE_OK);

    for (size_t i = 0; i < NUM_THREADS; i++)
        threads[i].join();
}

void* CBTestWaiterThread(void* args)
{
    oe_enclave_t* enclave = (oe_enclave_t*)args;

    OE_TEST(oe_call_enclave(enclave, "CBTestWaiterThreadImpl", NULL) == OE_OK);

    return NULL;
}

void* CBTestSignalThread(void* args)
{
    oe_enclave_t* enclave = (oe_enclave_t*)args;

    OE_TEST(oe_call_enclave(enclave, "CBTestSignalThreadImpl", NULL) == OE_OK);

    return NULL;
}

void TestCondBroadcast(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];
    std::thread signal_thread;

    printf("TestCondBroadcast Starting\n");

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i] = std::thread(CBTestWaiterThread, enclave);
    }

    signal_thread = std::thread(CBTestSignalThread, enclave);

    for (size_t i = 0; i < NUM_THREADS; i++)
        threads[i].join();

    signal_thread.join();

    printf("TestCondBroadcast Complete\n");
}

void* ExclusiveAccessThread(void* args)
{
    const size_t ITERS = 2;
    oe_enclave_t* enclave = (oe_enclave_t*)args;

    printf("Thread Starting\n");
    for (size_t i = 0; i < ITERS; i++)
    {
        OE_TEST(
            oe_call_enclave(enclave, "WaitForExclusiveAccess", NULL) == OE_OK);
        std::this_thread::sleep_for(std::chrono::microseconds(20 * 1000));

        OE_TEST(
            oe_call_enclave(enclave, "RelinquishExclusiveAccess", NULL) ==
            OE_OK);
        std::this_thread::sleep_for(std::chrono::microseconds(20 * 1000));
    }
    printf("Thread Ending\n");
    return NULL;
}

void TestThreadWakeWait(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];

    printf("TestThreadWakeWait Starting\n");
    for (size_t i = 0; i < NUM_THREADS; i++)
        threads[i] = std::thread(ExclusiveAccessThread, enclave);

    for (size_t i = 0; i < NUM_THREADS; i++)
        threads[i].join();

    // The oe_calls in this test should succeed without any segv/double free.
    printf("TestThreadWakeWait Complete\n");
}

void* LockAndUnlockThread1(void* args)
{
    oe_enclave_t* enclave = (oe_enclave_t*)args;

    const size_t ITERS = 20000;

    for (size_t i = 0; i < ITERS; ++i)
    {
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexes", (void*)"ABC") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexes", (void*)"AB") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexes", (void*)"AC") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexes", (void*)"BC") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexes", (void*)"ABBC") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexes", (void*)"ABAB") ==
            OE_OK);
    }

    return NULL;
}

void* LockAndUnlockThread2(void* args)
{
    oe_enclave_t* enclave = (oe_enclave_t*)args;

    const size_t ITERS = 20000;

    for (size_t i = 0; i < ITERS; ++i)
    {
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexes", (void*)"BC") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexes", (void*)"ABC") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexes", (void*)"BBCC") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexes", (void*)"BBC") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexes", (void*)"ABAB") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexes", (void*)"ABAC") ==
            OE_OK);
        OE_TEST(
            oe_call_enclave(enclave, "LockAndUnlockMutexes", (void*)"ABAB") ==
            OE_OK);
    }

    return NULL;
}

// Launch multiple threads and try out various locking patterns on 3 mutexes.
// The locking patterns are chosen to not deadlock.
void TestThreadLockingPatterns(oe_enclave_t* enclave)
{
    std::thread threads[NUM_THREADS];

    printf("TestThreadLockingPatterns Starting\n");
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i] = std::thread(
            (i & 1) ? LockAndUnlockThread2 : LockAndUnlockThread1, enclave);
    }

    for (size_t i = 0; i < NUM_THREADS; i++)
        threads[i].join();

    // The oe_calls in this test should succeed without any OE_TEST() failures.
    printf("TestThreadLockingPatterns Complete\n");
}

void TestReadersWriterLock(oe_enclave_t* enclave);

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

    TestMutex(enclave);

    TestCond(enclave);

    TestCondBroadcast(enclave);

    TestThreadWakeWait(enclave);

    TestThreadLockingPatterns(enclave);

    TestReadersWriterLock(enclave);

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
