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
#include <vector>
#include "../../../host/enclave.h"
#include "../args.h"

static TestMutexArgs _args;
static TestTCSArgs _tcsargs;

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
    static WaitArgs _waitargs = {NUM_THREADS};

    oe_result_t result = oe_call_enclave(enclave, "Wait", &_waitargs);
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
    {
        OE_TEST(oe_call_enclave(enclave, "Signal", NULL) == OE_OK);
    }

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

void* ThreadTCS(void* args)
{
    oe_enclave_t* enclave = (oe_enclave_t*)args;

    oe_result_t result =
        oe_call_enclave(enclave, "TestTCSExhaustion", &_tcsargs);
    if (result == OE_OUT_OF_THREADS)
        _tcsargs.num_out_threads++;
    else
        OE_TEST(result == OE_OK);

    return NULL;
}

// Thread binding test to verify TCS exhaustion i.e. enter on N threads when
// there are M TCSes where N > M; oe_call should return OE_OUT_OF_THREADS when
// M enclaves are in use.
// Trick is to keep the M enclaves busy until we get TCS exhaustion
void TestTCSExhaustion(oe_enclave_t* enclave)
{
    std::vector<std::thread> threads;
    // Set the test_tcs_count to a value greater than the enclave TCSCount
    size_t test_tcs_count = enclave->num_bindings * 3;
    printf(
        "TestTCSExhaust() - Number of TCS bindings in enclave=%zu\n",
        enclave->num_bindings);
    // Initialization of the shared variables before creating threads/launching
    // enclaves
    _tcsargs.num_threads = 0;
    _tcsargs.num_out_threads = 0;
    _tcsargs.tcs_count = test_tcs_count;

    for (size_t i = 0; i < test_tcs_count; i++)
    {
        threads.push_back(std::thread(ThreadTCS, enclave));
    }

    for (size_t i = 0; i < test_tcs_count; i++)
        threads[i].join();

    printf(
        "TestTCSExhaustion(): tcs_count=%d; num_threads=%d; "
        "num_out_threads=%d\n",
        (int)test_tcs_count,
        (int)_tcsargs.num_threads,
        (int)(int)_tcsargs.num_out_threads);
    if (!_tcsargs.num_out_threads)
        printf(
            "TestTCSExhaustion() FAILED as oe_call_enclave did not return "
            "OE_OUT_OF_THREADS\n");
    else
        printf(
            "TestTCSExhaustion() PASSED as oe_call_enclave returned "
            "OE_OUT_OF_THREADS\n");

    // Cleanup -- Removes all elements from the vector threads
    threads.clear();
    // Crux of the test is to get OE_OUT_OF_THREADS i.e. to exhaust the TCSes
    OE_TEST(_tcsargs.num_out_threads > 0);
    // Verifying that everything adds up fine
    OE_TEST(_tcsargs.num_threads + _tcsargs.num_out_threads == test_tcs_count);
    // Sanity test that we are not reusing the bindings
    OE_TEST(_tcsargs.num_threads <= enclave->num_bindings);
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

    TestMutex(enclave);

    TestCond(enclave);

    TestCondBroadcast(enclave);

    TestThreadWakeWait(enclave);

    TestThreadLockingPatterns(enclave);

    TestReadersWriterLock(enclave);

    TestTCSExhaustion(enclave);

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
