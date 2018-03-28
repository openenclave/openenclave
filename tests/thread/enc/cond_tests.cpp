// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/tests.h>
#include <openenclave/enclave.h>
#include "../args.h"

static OE_Mutex mutex = OE_MUTEX_INITIALIZER;
static OE_Cond cond = OE_COND_INITIALIZER;

// Number of waiting threads.
static volatile int num_waiting = 0;

// Number of woken up threads.
static volatile int num_woken = 0;

static volatile bool exit_thread = false;

OE_ECALL void CBTestWaiterThreadImpl(void* args)
{
    OE_MutexLock(&mutex);

    while (!exit_thread)
    {
        // Increment counter and wait.
        ++num_waiting;

        // Release mutex and wait.
        OE_CondWait(&cond, &mutex);

        // This thread owns the mutex.
        // After waking up, update counters.
        --num_waiting;
        ++num_woken;
    }

    OE_MutexUnlock(&mutex);
}

OE_ECALL void CBTestSignalThreadImpl(void* args)
{
    // Iterate for enough number of times to
    // detect any sporadic behavior.
    // Note: The original issue that the accompanying fix
    // addresses is a sporadic issue that can only be reliably
    // reproduced by using large iterations (>= 2000) and trying out various
    // numbers of waiter threads as this test does.
    const size_t ITERS = 2000;

    for (size_t i = 0; i < ITERS; ++i)
    {
        OE_MutexLock(&mutex);

        // No thread should wake up until broadcast.
        OE_TEST(num_woken == 0);

        // Signal waiting threads to wake up.
        // Stash the number of threads expected to wake up.
        // The number of waiting threads could be 0, 1 or max number of waiter
        // threads. This is by design to allow for testing these various
        // scenarios in a rapid manner.
        int num_expected = num_waiting;
        OE_CondBroadcast(&cond);

        OE_MutexUnlock(&mutex);

        // There is no guarantee whether the woken up threads
        // are scheduled for execution immediately.
        // Therefore, wait until expected number of threads are woken up.
        bool done = false;
        while (!done)
        {
            OE_MutexLock(&mutex);

            // No more than desired number of threads should be woken up.
            OE_TEST(num_woken <= num_expected);

            if (num_expected == num_woken)
            {
                // Test succeeded. Clear counter.
                num_woken = 0;
                done = true;
            }

            OE_MutexUnlock(&mutex);
        }
    }

    // Signal waiter threads to exit.
    OE_MutexLock(&mutex);

    exit_thread = true;
    OE_CondBroadcast(&cond);

    // Since the signal thread owns the mutex now, any running waiter thread
    // would be currently in a OE_CondWait or in a OE_MutexLock.
    // Once the signal thread releases the mutex, the waiter thread would return
    // from either of the calls and then check the exit_thread flag and quit.
    OE_MutexUnlock(&mutex);
}
