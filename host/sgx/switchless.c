// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/atomic.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/switchless.h>
#include "../calls.h"
#include "../hostthread.h"
#include "../ocalls.h"
#include "enclave.h"

#if __linux__
#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>

static void _worker_wait(oe_host_worker_context_t* context)
{
    if (__sync_val_compare_and_swap(&context->event, 1, 0) == 0)
    {
        do
        {
            syscall(
                __NR_futex,
                &context->event,
                FUTEX_WAIT_PRIVATE,
                0,
                NULL,
                NULL,
                0);
            // If context-> is still 0, then this is a spurious-wake.
            // Spurious-wakes are ignored by going back to FUTEX_WAIT.
            // Since FUTEX_WAIT uses atomic instructions to load event->value,
            // it is safe to use a non-atomic operation here.
        } while (context->event == 0);
    }
}

static void _worker_wake(oe_host_worker_context_t* context)
{
    // context->event is expected to be set to 1 by the enclave.
    // This function is called only when needed.
    __sync_val_compare_and_swap(&context->event, 0, 1);
    syscall(__NR_futex, &context->event, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
}

#else

static void _worker_wait(oe_host_worker_context_t* context)
{
    // If the event value is 1, then set it to zero.
    if (_InterlockedCompareExchange(&context->event, 0, 1) == 0)
    {
        // If the previous value was zero, then wait while value is zero.
        uint32_t zero = 0;
        WaitOnAddress(&context->event, &zero, sizeof(context->event), INFINITE);
    }
}

static void _worker_wake(oe_host_worker_context_t* context)
{
    // Enclave sets context->value to 1.
    // Wake up the waiting worker.
    WakeByAddressSingle(&context->event);
}

#endif

/**
 * Number of iterations an ocall worker thread would spin before going to sleep
 */
#define OE_HOST_WORKER_SPIN_COUNT_THRESHOLD (4096U)

/*
** The thread function that handles switchless ocalls
**
*/
static void* _switchless_ocall_worker(void* arg)
{
    oe_host_worker_context_t* context = (oe_host_worker_context_t*)arg;

    while (!context->is_stopping)
    {
        volatile oe_call_host_function_args_t* local_call_arg = NULL;
        if ((local_call_arg = context->call_arg) != NULL)
        {
            context->call_arg = NULL;

            oe_handle_call_host_function(
                (uint64_t)local_call_arg, context->enclave);

            context->total_spin_count += context->spin_count;
            context->spin_count = 0;
        }
        else
        {
            if (++context->spin_count >= OE_HOST_WORKER_SPIN_COUNT_THRESHOLD)
            {
                context->total_spin_count += context->spin_count;
                context->spin_count = 0;

                _worker_wait(context);
            }
        }
    }
    return NULL;
}

static oe_result_t oe_stop_worker_threads(oe_switchless_call_manager_t* manager)
{
    oe_result_t result = OE_UNEXPECTED;
    for (size_t i = 0; i < manager->num_host_workers; i++)
    {
        manager->host_worker_contexts[i].is_stopping = true;
        _worker_wake(&manager->host_worker_contexts[i]);

        OE_TRACE_INFO(
            "Switchless host worker thread %d spun for %lu times",
            i,
            manager->host_worker_contexts[i].total_spin_count);
    }

    for (size_t i = 0; i < manager->num_host_workers; i++)
    {
        if (manager->host_worker_threads[i] != (oe_thread_t)NULL)
            if (oe_thread_join(manager->host_worker_threads[i]))
                OE_RAISE(OE_THREAD_JOIN_ERROR);
    }

    result = OE_OK;
done:
    return result;
}

oe_result_t oe_start_switchless_manager(
    oe_enclave_t* enclave,
    size_t num_host_workers)
{
    oe_result_t result = OE_UNEXPECTED;
    uint64_t result_out = 0;
    oe_switchless_call_manager_t* manager = NULL;
    oe_host_worker_context_t* contexts = NULL;
    oe_thread_t* threads = NULL;

    if (num_host_workers < 1 || enclave == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (enclave->switchless_manager != NULL)
        OE_RAISE(OE_UNEXPECTED);

    // Limit the number of host workers to the number of thread bindings
    // because the maximum parallelism is dictated by the latter for
    // synchronous ocalls. We may need to revisit this for asynchronous
    // calls later.
    if (num_host_workers > enclave->num_bindings)
        num_host_workers = (uint32_t)enclave->num_bindings;

    // Allocate memory for the manager and its arrays
    manager = calloc(1, sizeof(oe_switchless_call_manager_t));
    if (manager == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    contexts = calloc(num_host_workers, sizeof(oe_host_worker_context_t));
    if (contexts == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    threads = calloc(num_host_workers, sizeof(oe_thread_t));
    if (threads == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    manager->num_host_workers = num_host_workers;
    manager->host_worker_contexts = contexts;
    manager->host_worker_threads = threads;

    // Start the worker threads, and assign each one a private context.
    for (size_t i = 0; i < num_host_workers; i++)
    {
        OE_TRACE_INFO("Creating switchless host worker thread %d\n", (int)i);
        manager->host_worker_contexts[i].enclave = enclave;
        if (oe_thread_create(
                &manager->host_worker_threads[i],
                _switchless_ocall_worker,
                &manager->host_worker_contexts[i]) != 0)
        {
            oe_stop_worker_threads(manager);
            OE_RAISE(OE_THREAD_CREATE_ERROR);
        }
    }

    // Each enclave has at most one switchless manager.
    enclave->switchless_manager = manager;

    // Inform the enclave about the switchless manager through an ECALL
    OE_CHECK(oe_ecall(
        enclave,
        OE_ECALL_INIT_CONTEXT_SWITCHLESS,
        (uint64_t)manager,
        &result_out));
    OE_CHECK((oe_result_t)result_out);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_stop_switchless_manager(oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    if (enclave != NULL && enclave->switchless_manager != NULL)
    {
        OE_CHECK(oe_stop_worker_threads(enclave->switchless_manager));
    }
    result = OE_OK;
done:
    return result;
}

void oe_handle_wake_host_worker(uint64_t arg)
{
    oe_host_worker_context_t* context = (oe_host_worker_context_t*)arg;
    _worker_wake(context);
}
