// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <unistd.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../args.h"
#include "../rwlock_tests.h"

static TestRWLockArgs _rwArgs;

OE_OCALL void host_usleep(void* args)
{
    usleep((size_t)args);
}

void* ReaderThread(void* args)
{
    OE_Enclave* enclave = (OE_Enclave*)args;
    OE_TEST(OE_CallEnclave(enclave, "ReaderThreadImpl", &_rwArgs) == OE_OK);

    return NULL;
}

void* WriterThread(void* args)
{
    OE_Enclave* enclave = (OE_Enclave*)args;
    OE_TEST(OE_CallEnclave(enclave, "WriterThreadImpl", &_rwArgs) == OE_OK);

    return NULL;
}

// Launch multiple reader and writer threads and OE_TEST invariants.
void TestReadersWriterLock(OE_Enclave* enclave)
{
    pthread_t threads[NUM_RW_TEST_THREADS];

    memset(&_rwArgs, 0, sizeof(_rwArgs));

    for (size_t i = 0; i < NUM_RW_TEST_THREADS; i++)
    {
        pthread_create(
            &threads[i], NULL, (i & 1) ? WriterThread : ReaderThread, enclave);
    }

    for (size_t i = 0; i < NUM_RW_TEST_THREADS; i++)
        pthread_join(threads[i], NULL);

    // There can be at most 1 writer thread active.
    OE_TEST(_rwArgs.maxWriters == 1);

    // There can be at most NUM_THREADS/2 reader threads active
    // and no thread was starved.
    OE_TEST(_rwArgs.maxReaders <= NUM_READER_THREADS);

    // Readers and writer threads should never be simultaneously active.
    OE_TEST(_rwArgs.readersAndWriters == false);

    // Additionally, the test requires that all readers are
    // simultaneously active at least once.
    OE_TEST(_rwArgs.maxReaders == NUM_READER_THREADS);
}
