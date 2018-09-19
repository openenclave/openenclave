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
#include "../rwlock_tests.h"

static TestRWLockArgs _rw_args;

OE_OCALL void host_usleep(void* args)
{
    std::this_thread::sleep_for(std::chrono::microseconds((size_t)args));
}

void* ReaderThread(void* args)
{
    oe_enclave_t* enclave = (oe_enclave_t*)args;
    OE_TEST(oe_call_enclave(enclave, "ReaderThreadImpl", &_rw_args) == OE_OK);

    return NULL;
}

void* WriterThread(void* args)
{
    oe_enclave_t* enclave = (oe_enclave_t*)args;
    OE_TEST(oe_call_enclave(enclave, "WriterThreadImpl", &_rw_args) == OE_OK);

    return NULL;
}

// Launch multiple reader and writer threads and OE_TEST invariants.
void TestReadersWriterLock(oe_enclave_t* enclave)
{
    std::thread threads[NUM_RW_TEST_THREADS];

    memset(&_rw_args, 0, sizeof(_rw_args));

    for (size_t i = 0; i < NUM_RW_TEST_THREADS; i++)
    {
        threads[i] =
            std::thread((i & 1) ? WriterThread : ReaderThread, enclave);
    }

    for (size_t i = 0; i < NUM_RW_TEST_THREADS; i++)
        threads[i].join();

    // There can be at most 1 writer thread active.
    OE_TEST(_rw_args.max_writers == 1);

    // There can be at most NUM_THREADS/2 reader threads active
    // and no thread was starved.
    OE_TEST(_rw_args.max_readers <= NUM_READER_THREADS);

    // Readers and writer threads should never be simultaneously active.
    OE_TEST(_rw_args.readers_and_writers == false);

    // Additionally, the test requires that all readers are
    // simultaneously active at least once.
    OE_TEST(_rw_args.max_readers == NUM_READER_THREADS);
}
