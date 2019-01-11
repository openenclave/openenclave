// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifdef _PTHREAD_ENC_
#include "thread.h"
#endif

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/thread.h>
#include <stdio.h>
#include <stdlib.h>
#include "thread_t.h"

static oe_mutex_t mutex = OE_MUTEX_INITIALIZER;
static oe_cond_t cond = OE_COND_INITIALIZER;

// Number of waiting threads.
static volatile int num_waiting = 0;

// Number of woken up threads.
static volatile int num_woken = 0;

static volatile bool exit_thread = false;

void cb_test_waiter_thread_impl()
{
    oe_mutex_lock(&mutex);

    while (!exit_thread)
    {
        // Increment counter and wait.
        ++num_waiting;

        // Release mutex and wait.
        oe_cond_wait(&cond, &mutex);

        // This thread owns the mutex.
        // After waking up, update counters.
        --num_waiting;
        ++num_woken;
    }

    oe_mutex_unlock(&mutex);
}

void cb_test_signal_thread_impl()
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
        oe_mutex_lock(&mutex);

        // No thread should wake up until broadcast.
        OE_TEST(num_woken == 0);

        // Signal waiting threads to wake up.
        // Stash the number of threads expected to wake up.
        // The number of waiting threads could be 0, 1 or max number of waiter
        // threads. This is by design to allow for testing these various
        // scenarios in a rapid manner.
        int num_expected = num_waiting;
        oe_cond_broadcast(&cond);

        oe_mutex_unlock(&mutex);

        // There is no guarantee whether the woken up threads
        // are scheduled for execution immediately.
        // Therefore, wait until expected number of threads are woken up.
        bool done = false;
        while (!done)
        {
            oe_mutex_lock(&mutex);

            // No more than desired number of threads should be woken up.
            OE_TEST(num_woken <= num_expected);

            if (num_expected == num_woken)
            {
                // Test succeeded. Clear counter.
                num_woken = 0;
                done = true;
            }

            oe_mutex_unlock(&mutex);
        }
    }

    // Signal waiter threads to exit.
    oe_mutex_lock(&mutex);

    exit_thread = true;
    oe_cond_broadcast(&cond);

    // Since the signal thread owns the mutex now, any running waiter thread
    // would be currently in a oe_cond_wait or in a oe_mutex_lock.
    // Once the signal thread releases the mutex, the waiter thread would return
    // from either of the calls and then check the exit_thread flag and quit.
    oe_mutex_unlock(&mutex);
}
