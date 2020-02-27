// Copyright (c) Open Enclave SDK contributors.
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
#include "switchless_u.h"

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
            // Handle the switchless call, but do not clear the slot yet. Since
            // the slot is not empty, any new incoming switchless call request
            // will be scheduled in another available work thread and get
            // handled immediately.
            oe_handle_call_host_function(
                (uint64_t)local_call_arg, context->enclave);

            // After handling the switchless call, mark this worker thread
            // as free by clearing the slot.
            context->call_arg = NULL;

            // Reset spin count for next message.
            context->total_spin_count += context->spin_count;
            context->spin_count = 0;
        }
        else
        {
            // If there is no message, increment spin count until threshold is
            // reached.
            if (++context->spin_count >= OE_HOST_WORKER_SPIN_COUNT_THRESHOLD)
            {
                // Reset spin count and go to sleep until event is fired.
                context->total_spin_count += context->spin_count;
                context->spin_count = 0;
                oe_host_worker_wait(context);
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
        oe_host_worker_wake(&manager->host_worker_contexts[i]);

        OE_TRACE_INFO(
            "Switchless host worker thread %d spun for %lu times",
            (int)i,
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
    oe_result_t result_out = 0;
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
    OE_CHECK(oe_init_context_switchless_ecall(
        enclave,
        &result_out,
        manager->host_worker_contexts,
        manager->num_host_workers));
    OE_CHECK(result_out);

    result = OE_OK;

done:
    if (result != OE_OK)
    {
        if (manager)
        {
            free(manager);
            enclave->switchless_manager = NULL;
        }

        if (contexts)
            free(contexts);

        if (threads)
            free(threads);
    }

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

void oe_wake_switchless_worker_ocall(oe_host_worker_context_t* context)
{
    oe_host_worker_wake(context);
}
