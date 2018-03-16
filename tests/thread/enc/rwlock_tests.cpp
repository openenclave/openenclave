// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>
#include "../args.h"

static OE_RWLock rwLock = OE_RWLOCK_INITIALIZER;
static OE_Spinlock rwArgsLock = OE_SPINLOCK_INITIALIZER;
static const size_t RWLOCK_TEST_ITERS = 100;

inline size_t max(size_t a, size_t b)
{
    return (a > b) ? a : b;
}

class ScopedSpinLock
{
  public:
    ScopedSpinLock(OE_Spinlock* s) : lock(s)
    {
        OE_SpinLock(lock);
    }

    ~ScopedSpinLock()
    {
        OE_SpinUnlock(lock);
    }

  private:
    ScopedSpinLock(const ScopedSpinLock&);
    ScopedSpinLock& operator=(const ScopedSpinLock&);

  private:
    OE_Spinlock* lock;
};

OE_ECALL void ReaderThreadImpl(void* args_)
{
    TestRWLockArgs* args = (TestRWLockArgs*)args_;

    for (size_t i = 0; i < RWLOCK_TEST_ITERS; ++i)
    {
        // Obtain read lock
        OE_RWLockReadLock(&rwLock);

        {
            // Update test data
            ScopedSpinLock lock(&rwArgsLock);

            ++args->readers;

            // Maximum number of simultaneous readers
            args->maxReaders = max(args->maxReaders, args->readers);

            // Are readers and writers simultaneously active?
            args->readersAndWriters =
                args->readersAndWriters || (args->readers && args->writers);

            --args->readers;
        }

        // Release read lock
        OE_RWLockReadUnlock(&rwLock);
    }

    OE_HostPrintf("%ld: Reader Exiting\n", OE_ThreadSelf());
}

OE_ECALL void WriterThreadImpl(void* args_)
{
    TestRWLockArgs* args = (TestRWLockArgs*)args_;

    for (size_t i = 0; i < RWLOCK_TEST_ITERS; ++i)
    {
        // Obtain write lock
        OE_RWLockWriteLock(&rwLock);

        {
            // Update test data
            ScopedSpinLock lock(&rwArgsLock);

            ++args->writers;

            // Maximum number of simultaneous writers
            args->maxWriters = max(args->maxWriters, args->writers);

            // Are readers and writers simultaneously active?
            args->readersAndWriters =
                args->readersAndWriters || (args->readers && args->writers);

            --args->writers;
        }

        // Release write lock
        OE_RWLockWriteUnlock(&rwLock);
    }

    OE_HostPrintf("%ld: Writer Exiting\n", OE_ThreadSelf());
}
