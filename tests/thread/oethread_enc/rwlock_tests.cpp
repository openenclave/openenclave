// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../rwlock_tests.h"
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/thread.h>
#include <stdio.h>
#include <stdlib.h>
#include "../args.h"

static oe_rwlock_t rwLock = OE_RWLOCK_INITIALIZER;
static oe_spinlock_t rwArgsLock = OE_SPINLOCK_INITIALIZER;

inline size_t max(size_t a, size_t b)
{
    return (a > b) ? a : b;
}

class ScopedSpinLock
{
  public:
    ScopedSpinLock(oe_spinlock_t* s) : slock(s)
    {
        oe_spin_lock(slock);
    }

    void Lock()
    {
        oe_spin_lock(slock);
    }

    void Unlock()
    {
        oe_spin_unlock(slock);
    }

    ~ScopedSpinLock()
    {
        oe_spin_unlock(slock);
    }

  private:
    ScopedSpinLock(const ScopedSpinLock&);
    ScopedSpinLock& operator=(const ScopedSpinLock&);

  private:
    oe_spinlock_t* slock;
};

OE_ECALL void ReaderThreadImpl(void* args_)
{
    TestRWLockArgs* args = (TestRWLockArgs*)args_;

    for (size_t i = 0; i < RWLOCK_TEST_ITERS; ++i)
    {
        // Obtain read lock.
        oe_rwlock_rdlock(&rwLock);

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
                oe_call_host("host_usleep", (void*)sleep_utime);
                lock.Lock();
            }

            // Are readers and writers simultaneously active?
            args->readersAndWriters =
                args->readersAndWriters || (args->readers && args->writers);
        }

        // Hold on to the lock for some time to test ownership constraints.
        // Multiple readers should be allowed.
        oe_call_host("host_usleep", (void*)sleep_utime);

        {
            // Update test data.
            ScopedSpinLock lock(&rwArgsLock);

            // Are readers and writers simultaneously active?
            args->readersAndWriters =
                args->readersAndWriters || (args->readers && args->writers);

            --args->readers;
        }

        // Release read lock
        oe_rwlock_rdunlock(&rwLock);
    }

    oe_host_printf("%llu: Reader Exiting\n", OE_LLU(oe_thread_self()));
}

OE_ECALL void WriterThreadImpl(void* args_)
{
    TestRWLockArgs* args = (TestRWLockArgs*)args_;

    for (size_t i = 0; i < RWLOCK_TEST_ITERS; ++i)
    {
        // Obtain write lock
        oe_rwlock_wrlock(&rwLock);

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
        oe_call_host("host_usleep", (void*)sleep_utime);

        {
            // Update test data
            ScopedSpinLock lock(&rwArgsLock);

            // Are readers and writers simultaneously active?
            args->readersAndWriters =
                args->readersAndWriters || (args->readers && args->writers);

            --args->writers;
        }

        // Release write lock
        oe_rwlock_wrunlock(&rwLock);
    }

    oe_host_printf("%llu: Writer Exiting\n", OE_LLU(oe_thread_self()));
}
