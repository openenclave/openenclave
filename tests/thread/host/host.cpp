// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
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
    assert(result == OE_OK);

    return NULL;
}

void TestMutex(OE_Enclave* enclave)
{
    pthread_t threads[NUM_THREADS];

    for (size_t i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, Thread, enclave);

    for (size_t i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    assert(_args.count1 == NUM_THREADS);
    assert(_args.count2 == NUM_THREADS);
}

void* WaiterThread(void* args)
{
    OE_Enclave* enclave = (OE_Enclave*)args;
    static WaitArgs _args = { NUM_THREADS };

    OE_Result result = OE_CallEnclave(enclave, "Wait", &_args);
    assert(result == OE_OK);

    return NULL;
}

void TestCond(OE_Enclave* enclave)
{
    pthread_t threads[NUM_THREADS];

    for (size_t i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, WaiterThread, enclave);

    sleep(1);

    for (size_t i = 0; i < NUM_THREADS; i++)
        assert(OE_CallEnclave(enclave, "Signal", NULL) == OE_OK);

    for (size_t i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
}

void* ExclusiveAccessThread(void* args)
{
    const size_t ITERS = 2;
    OE_Enclave* enclave = (OE_Enclave*)args;

    printf("Thread Starting\n");
    for (size_t i = 0; i < ITERS; i++)
    {
        assert(
            OE_CallEnclave(enclave, "WaitForExclusiveAccess", NULL) == OE_OK);
        usleep(20 * 1000);

        assert(
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

    TestThreadWakeWait(enclave);

    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
    {
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
