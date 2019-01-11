// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>
#include "threadcxx_t.h"

static std::mutex mutex;
static std::condition_variable cond;

// Number of waiting threads.
static int num_waiting = 0;

// Number of woken up threads.
static int num_woken = 0;

static volatile bool exit_thread = false;

void enc_test_cb_cxx_waiter()
{
    std::unique_lock<std::mutex> lock(mutex);

    while (!exit_thread)
    {
        // Increment counter and wait.
        ++num_waiting;

        // Release mutex and wait.
        cond.wait(lock);

        // This thread owns the mutex.
        // After waking up, update counters.
        --num_waiting;
        ++num_woken;
    }
}

void enc_test_cb_cxx_signal()
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
        int num_expected;
        {
            std::unique_lock<std::mutex> lock(mutex);

            // No thread should wake up until broadcast.
            OE_TEST(num_woken == 0);

            // Signal waiting threads to wake up.
            // Stash the number of threads expected to wake up.
            // The number of waiting threads could be 0, 1 or max number of
            // waiter threads. This is by design to allow for testing these
            // various scenarios in a rapid manner.
            num_expected = num_waiting;
            cond.notify_all();
        }

        // There is no guarantee whether the woken up threads
        // are scheduled for execution immediately.
        // Therefore, wait until expected number of threads are woken up.
        bool done = false;
        while (!done)
        {
            std::lock_guard<std::mutex> lg1_lock(mutex);

            // No more than desired number of threads should be woken up.
            OE_TEST(num_woken <= num_expected);

            if (num_expected == num_woken)
            {
                // Test succeeded. Clear counter.
                num_woken = 0;
                done = true;
            }
        }
    }

    // Signal waiter threads to exit.
    std::lock_guard<std::mutex> lg2_lock(mutex);

    exit_thread = true;
    cond.notify_all();

    // Since the signal thread owns the mutex now, any running waiter thread
    // would be currently in a oe_cond_wait or in a oe_mutex_lock.
    // Once the signal thread releases the mutex, the waiter thread would return
    // from either of the calls and then check the exit_thread flag and quit.
}
