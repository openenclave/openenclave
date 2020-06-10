// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <Windows.h>
#include <openenclave/internal/switchless.h>

static void _worker_wait(volatile long* event)
{
    // If event is 1, it means that there a pending wake notification from
    // enclave. Consume it by setting event to 0. Don't wait.
    //
    // If event is 0, then wait until event is 1.
    int32_t oldval = 1;
    int32_t newval = 0;

    if (_InterlockedCompareExchange(event, newval, oldval) == 0)
    {
        // If the previous value was zero, then wait while value is zero.
        uint32_t zero = 0;
        WaitOnAddress(event, &zero, sizeof(*event), INFINITE);
    }
}

static void _worker_wake(volatile long* event)
{
    // Set the event and wake up the worker.
    *event = 1;
    WakeByAddressSingle((void*)event);
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
    _worker_wait((long*)&context->event);
}

void oe_enclave_worker_wake(oe_enclave_worker_context_t* context)
{
    _worker_wake(&context->event);
}
