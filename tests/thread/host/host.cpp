// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/error.h>
#include <openenclave/bits/tests.h>
#include <openenclave/host.h>
#include <pthread.h>
#include <unistd.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../args.h"

static TestMutexArgs _args;

const size_t NUM_THREADS = 8;

void* Thread(void* args)
{
    OE_Enclave* enclave = (OE_Enclave*)args;

    OE_Result result = OE_CallEnclave(enclave, "TestMutex", &_args);
    OE_TEST(result == OE_OK);

    return NULL;
}

void TestMutex(OE_Enclave* enclave)
{
    pthread_t threads[NUM_THREADS];

    for (size_t i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, Thread, enclave);

    for (size_t i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    OE_TEST(_args.count1 == NUM_THREADS);
    OE_TEST(_args.count2 == NUM_THREADS);
}

void* WaiterThread(void* args)
{
    OE_Enclave* enclave = (OE_Enclave*)args;
    static WaitArgs _args = {NUM_THREADS};

    OE_Result result = OE_CallEnclave(enclave, "Wait", &_args);
    OE_TEST(result == OE_OK);

    return NULL;
}

void TestCond(OE_Enclave* enclave)
{
    pthread_t threads[NUM_THREADS];

    for (size_t i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, WaiterThread, enclave);

    sleep(1);

    for (size_t i = 0; i < NUM_THREADS; i++)
        OE_TEST(OE_CallEnclave(enclave, "Signal", NULL) == OE_OK);

    for (size_t i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
}

void* CBTestWaiterThread(void* args)
{
    OE_Enclave* enclave = (OE_Enclave*)args;

    OE_TEST(OE_CallEnclave(enclave, "CBTestWaiterThreadImpl", NULL) == OE_OK);

    return NULL;
}

void* CBTestSignalThread(void* args)
{
    OE_Enclave* enclave = (OE_Enclave*)args;

    OE_TEST(OE_CallEnclave(enclave, "CBTestSignalThreadImpl", NULL) == OE_OK);

    return NULL;
}

void TestCondBroadcast(OE_Enclave* enclave)
{
    pthread_t threads[NUM_THREADS];
    pthread_t signal_thread;

    printf("TestCondBroadcast Starting\n");

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        pthread_create(&threads[i], NULL, CBTestWaiterThread, enclave);
    }

    pthread_create(&signal_thread, NULL, CBTestSignalThread, enclave);

    for (size_t i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    pthread_join(signal_thread, NULL);

    printf("TestCondBroadcast Complete\n");
}

void* ExclusiveAccessThread(void* args)
{
    const size_t ITERS = 2;
    OE_Enclave* enclave = (OE_Enclave*)args;

    printf("Thread Starting\n");
    for (size_t i = 0; i < ITERS; i++)
    {
        OE_TEST(
            OE_CallEnclave(enclave, "WaitForExclusiveAccess", NULL) == OE_OK);
        usleep(20 * 1000);

        OE_TEST(
            OE_CallEnclave(enclave, "RelinquishExclusiveAccess", NULL) ==
            OE_OK);
        usleep(20 * 1000);
    }
    printf("Thread Ending\n");
    return NULL;
}

void TestThreadWakeWait(OE_Enclave* enclave)
{
    pthread_t threads[NUM_THREADS];

    printf("TestThreadWakeWait Starting\n");
    for (size_t i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, ExclusiveAccessThread, enclave);

    for (size_t i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    // The OE_Calls in this test should succeed without any segv/double free.
    printf("TestThreadWakeWait Complete\n");
}

void* LockAndUnlockThread1(void* args)
{
    OE_Enclave* enclave = (OE_Enclave*)args;

    const size_t ITERS = 20000;

    for (size_t i = 0; i < ITERS; ++i)
    {
        OE_TEST(
            OE_CallEnclave(enclave, "LockAndUnlockMutexes", (void*)"ABC") ==
            OE_OK);
        OE_TEST(
            OE_CallEnclave(enclave, "LockAndUnlockMutexes", (void*)"AB") ==
            OE_OK);
        OE_TEST(
            OE_CallEnclave(enclave, "LockAndUnlockMutexes", (void*)"AC") ==
            OE_OK);
        OE_TEST(
            OE_CallEnclave(enclave, "LockAndUnlockMutexes", (void*)"BC") ==
            OE_OK);
        OE_TEST(
            OE_CallEnclave(enclave, "LockAndUnlockMutexes", (void*)"ABBC") ==
            OE_OK);
        OE_TEST(
            OE_CallEnclave(enclave, "LockAndUnlockMutexes", (void*)"ABAB") ==
            OE_OK);
    }

    return NULL;
}

void* LockAndUnlockThread2(void* args)
{
    OE_Enclave* enclave = (OE_Enclave*)args;

    const size_t ITERS = 20000;

    for (size_t i = 0; i < ITERS; ++i)
    {
        OE_TEST(
            OE_CallEnclave(enclave, "LockAndUnlockMutexes", (void*)"BC") ==
            OE_OK);
        OE_TEST(
            OE_CallEnclave(enclave, "LockAndUnlockMutexes", (void*)"ABC") ==
            OE_OK);
        OE_TEST(
            OE_CallEnclave(enclave, "LockAndUnlockMutexes", (void*)"BBCC") ==
            OE_OK);
        OE_TEST(
            OE_CallEnclave(enclave, "LockAndUnlockMutexes", (void*)"BBC") ==
            OE_OK);
        OE_TEST(
            OE_CallEnclave(enclave, "LockAndUnlockMutexes", (void*)"ABAB") ==
            OE_OK);
        OE_TEST(
            OE_CallEnclave(enclave, "LockAndUnlockMutexes", (void*)"ABAC") ==
            OE_OK);
        OE_TEST(
            OE_CallEnclave(enclave, "LockAndUnlockMutexes", (void*)"ABAB") ==
            OE_OK);
    }

    return NULL;
}

// Lauch multiple threads and try out various locking patterns on 3 mutexes.
// The locking patterns are chosen to not deadlock.
void TestThreadLockingPatterns(OE_Enclave* enclave)
{
    pthread_t threads[NUM_THREADS];

    printf("TestThreadLockingPatterns Starting\n");
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        pthread_create(
            &threads[i],
            NULL,
            (i & 1) ? LockAndUnlockThread2 : LockAndUnlockThread1,
            enclave);
    }

    for (size_t i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    // The OE_Calls in this test should succeed without any OE_TESTions.
    printf("TestThreadLockingPatterns Complete\n");
}

void TestReadersWriterLock(OE_Enclave* enclave);

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = OE_GetCreateFlags();

    if ((result = OE_CreateEnclave(argv[1], flags, &enclave)) != OE_OK)
    {
        OE_PutErr("OE_CreateEnclave(): result=%u", result);
    }

    TestMutex(enclave);

    TestCond(enclave);

    TestCondBroadcast(enclave);

    TestThreadWakeWait(enclave);

    TestThreadLockingPatterns(enclave);

    TestReadersWriterLock(enclave);

    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
    {
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
