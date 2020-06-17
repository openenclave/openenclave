// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/switchless.h>

#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>

static void _worker_wait(volatile int* event)
{
    // If event is 1, it means that there a pending wake notification from
    // enclave. Consume it by setting event to 0. Don't wait.
    //
    // If event is 0, then wait until event is 1.
    int32_t oldval = 1;
    int32_t newval = 0;

    // Weak operations can fail spuriously.
    // We want a strong operation.
    bool weak = false;
    if (!__atomic_compare_exchange_n(
            event, &oldval, newval, weak, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
    {
        // The old value is 0. There is no pending wake notification from the
        // enclave.
        do
        {
            // Error codes from syscall are ignored since we wait until event
            // is non-zero.
            syscall(__NR_futex, event, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
            // If context->event is still 0, then this is a spurious-wake.
            // Spurious-wakes are ignored by going back to FUTEX_WAIT.
            // Since FUTEX_WAIT uses atomic instructions to load event->value,
            // it is safe to use a non-atomic operation here.
        } while (*event == 0);
    }
}

static void _worker_wake(volatile int* event)
{
    *event = 1;
    syscall(
        __NR_futex,
        event,
        FUTEX_WAKE_PRIVATE,
        1 /* wake 1 thread */,
        NULL,
        NULL,
        0);
}

void oe_host_worker_wait(oe_host_worker_context_t* context)
{
    _worker_wait(&context->event);
}

void oe_host_worker_wake(oe_host_worker_context_t* context)
{
    _worker_wake(&context->event);
}

void oe_enclave_worker_wait(oe_enclave_worker_context_t* context)
{
    _worker_wait(&context->event);
}

void oe_enclave_worker_wake(oe_enclave_worker_context_t* context)
{
    _worker_wake(&context->event);
}
