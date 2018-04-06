// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../rwlock_tests.h"
#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>
#include "../args.h"

static OE_RWLock rwLock = OE_RWLOCK_INITIALIZER;
static OE_Spinlock rwArgsLock = OE_SPINLOCK_INITIALIZER;

inline size_t max(size_t a, size_t b)
{
    return (a > b) ? a : b;
}

class ScopedSpinLock
{
  public:
    ScopedSpinLock(OE_Spinlock* s) : slock(s)
    {
        OE_SpinLock(slock);
    }

    void Lock()
    {
        OE_SpinLock(slock);
    }

    void Unlock()
    {
        OE_SpinUnlock(slock);
    }

    ~ScopedSpinLock()
    {
        OE_SpinUnlock(slock);
    }

  private:
    ScopedSpinLock(const ScopedSpinLock&);
    ScopedSpinLock& operator=(const ScopedSpinLock&);

  private:
    OE_Spinlock* slock;
};

OE_ECALL void ReaderThreadImpl(void* args_)
{
    TestRWLockArgs* args = (TestRWLockArgs*)args_;

    for (size_t i = 0; i < RWLOCK_TEST_ITERS; ++i)
    {
        // Obtain read lock.
        OE_RWLockReadLock(&rwLock);

        {
            // Update test data.
            ScopedSpinLock lock(&rwArgsLock);

            ++args->readers;

            // Maximum number of simultaneous readers.
            args->maxReaders = max(args->maxReaders, args->readers);

            // Allow all reader threads to be simultaneously active
            // at least once.
            while (args->maxReaders < NUM_READER_THREADS)
            {
                lock.Unlock();
                OE_CallHost("host_usleep", (void*)sleep_utime);
                lock.Lock();
            }

            // Are readers and writers simultaneously active?
            args->readersAndWriters =
                args->readersAndWriters || (args->readers && args->writers);
        }

        // Hold on to the lock for some time to test ownership constraints.
        // Multiple readers should be allowed.
        OE_CallHost("host_usleep", (void*)sleep_utime);

        {
            // Update test data.
            ScopedSpinLock lock(&rwArgsLock);

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
        }

        // Hold on to the lock for some time to test ownership constraints.
        // Only one writer should be allowed.
        OE_CallHost("host_usleep", (void*)sleep_utime);

        {
            // Update test data
            ScopedSpinLock lock(&rwArgsLock);

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
