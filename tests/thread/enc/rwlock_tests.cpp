// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef _PTHREAD_ENC_
#include "thread.h"
#endif

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include "../rwlock_tests.h"
#include "thread_t.h"

static oe_rwlock_t rw_lock = OE_RWLOCK_INITIALIZER;
static oe_spinlock_t rw_args_lock = OE_SPINLOCK_INITIALIZER;

static size_t g_readers = 0;
static size_t g_writers = 0;
static size_t g_max_readers = 0;
static size_t g_max_writers = 0;
static bool g_readers_and_writers = false;

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

void enc_reader_thread_impl()
{
    for (size_t i = 0; i < RWLOCK_TEST_ITERS; ++i)
    {
        // Obtain read lock.
        oe_rwlock_rdlock(&rw_lock);

        {
            // Update test data.
            ScopedSpinLock lock(&rw_args_lock);

            ++g_readers;

            // Maximum number of simultaneous readers.
            g_max_readers = std::max(g_max_readers, g_readers);

            // Allow all reader threads to be simultaneously active
            // at least once.
            while (g_max_readers < NUM_READER_THREADS)
            {
                lock.Unlock();
                host_usleep(sleep_utime);
                lock.Lock();
            }

            // Are readers and writers simultaneously active?
            g_readers_and_writers =
                g_readers_and_writers || (g_readers && g_writers);
        }

        // Hold on to the lock for some time to test ownership constraints.
        // Multiple readers should be allowed.
        host_usleep(sleep_utime);

        {
            // Update test data.
            ScopedSpinLock lock(&rw_args_lock);

            // Are readers and writers simultaneously active?
            g_readers_and_writers =
                g_readers_and_writers || (g_readers && g_writers);

            --g_readers;
        }

        // Release read lock
        oe_rwlock_unlock(&rw_lock);
    }

    oe_host_printf("%llu: Reader Exiting\n", OE_LLU(oe_thread_self()));
}

void enc_writer_thread_impl()
{
    for (size_t i = 0; i < RWLOCK_TEST_ITERS; ++i)
    {
        // Obtain write lock
        oe_rwlock_wrlock(&rw_lock);

        {
            // Update test data
            ScopedSpinLock lock(&rw_args_lock);

            ++g_writers;

            // Maximum number of simultaneous writers
            g_max_writers = std::max(g_max_writers, g_writers);

            // Are readers and writers simultaneously active?
            g_readers_and_writers =
                g_readers_and_writers || (g_readers && g_writers);
        }

        // Hold on to the lock for some time to test ownership constraints.
        // Only one writer should be allowed.
        host_usleep(sleep_utime);

        {
            // Update test data
            ScopedSpinLock lock(&rw_args_lock);

            // Are readers and writers simultaneously active?
            g_readers_and_writers =
                g_readers_and_writers || (g_readers && g_writers);

            --g_writers;
        }

        // Release write lock
        oe_rwlock_unlock(&rw_lock);
    }

    oe_host_printf("%llu: Writer Exiting\n", OE_LLU(oe_thread_self()));
}

void enc_rw_results(
    size_t* readers,
    size_t* writers,
    size_t* max_readers,
    size_t* max_writers,
    bool* readers_and_writers)
{
    *readers = g_readers;
    *writers = g_writers;
    *max_readers = g_max_readers;
    *max_writers = g_max_writers;
    *readers_and_writers = g_readers_and_writers;
}
