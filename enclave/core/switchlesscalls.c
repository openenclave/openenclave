// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "switchlesscalls.h"
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/atomic.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>

// The number of host thread workers. Initialized by host through ECALL
static size_t _host_worker_count = 0;

// The array of host worker contexts. Initialized by host through ECALL
static oe_host_worker_context_t* _host_worker_contexts = NULL;

/*
**==============================================================================
**
** oe_is_switchless_initialized
**
** Return whether oe_handle_init_switchless has been called or not.
**
**==============================================================================
*/
bool oe_is_switchless_initialized()
{
    return _host_worker_count != 0;
}

/*
**==============================================================================
**
** oe_handle_init_switchless()
**
** Handle the OE_ECALL_INIT_CONTEXT_SWITCHLESS from host.
**
**==============================================================================
*/
oe_result_t oe_handle_init_switchless(uint64_t arg_in)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_switchless_call_manager_t* manager = NULL;
    oe_switchless_call_manager_t safe_manager;
    size_t contexts_size, threads_size;

    if (arg_in == 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    manager = (oe_switchless_call_manager_t*)arg_in;
    safe_manager = *manager;

    contexts_size =
        sizeof(oe_host_worker_context_t) * safe_manager.num_host_workers;
    threads_size = sizeof(oe_thread_t) * safe_manager.num_host_workers;

    // Ensure the switchless manager and its arrays are outside of enclave
    if (!oe_is_outside_enclave(manager, sizeof(oe_switchless_call_manager_t)) ||
        !oe_is_outside_enclave(
            safe_manager.host_worker_contexts, contexts_size) ||
        !oe_is_outside_enclave(
            safe_manager.host_worker_threads, threads_size) ||
        safe_manager.num_host_workers == 0)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* lfence after checks. */
    oe_lfence();

    // Copy the worker context array pointer and its size to avoid TOCTOU
    _host_worker_count = safe_manager.num_host_workers;
    _host_worker_contexts = safe_manager.host_worker_contexts;
    result = OE_OK;

done:
    return result;
}

/*
**==============================================================================
**
** oe_post_switchless_ocall()
**
**  Post the function call (wrapped in args) to a free host worker thread
**  by writing to its context.
**
**==============================================================================
*/
oe_result_t oe_post_switchless_ocall(oe_call_host_function_args_t* args)
{
    oe_result_t result = OE_UNEXPECTED;

    OE_ATOMIC_MEMORY_BARRIER_RELEASE();
    args->result = __OE_RESULT_MAX; // Means the call hasn't been processed.

    // Cycle through the worker contexts until we find a free worker.
    size_t tries = _host_worker_count;
    while (tries--)
    {
        // Check if the worker's slot is free.
        if (_host_worker_contexts[tries].call_arg == NULL)
        {
            // Try to atomically grab the slot by placing args in the slot.
            // If the atomic operation was successful, then the worker thread
            // will execute this switchless ocall. If the atomic operation
            // failed, this means that the slot was grabbed by another
            // switchless ocall and therefore, we must scan for another worker
            // thread with a free slot.
            if (oe_atomic_compare_and_swap_ptr(
                    (void* volatile*)&_host_worker_contexts[tries].call_arg,
                    NULL,
                    args))
            {
                // The worker thread has been marked to execute this switchless
                // call. Determine if it needs to be woken up or not.
                //
                // If event is 0, it means that it has gone to sleep. Wake it by
                // making an ocall (OE_OCALL_WAKE_HOST_WORKER).
                // Note: it is important to use an atomic cas operation to set
                // the value to 1 before making the ocall. Setting the value to
                // 1 prevents the host worker from simulataneously going to
                // sleep. If instead, just a compare operation is used to
                // determine if the host thread is sleeping or not, the host
                // thread could go to sleep after the enclave has determined
                // that the host is not sleeping, causing a deadlock.
                //
                // If event is 1, that indicates a pending wake notification.
                int32_t oldval = 0;
                int32_t newval = 1;
                // Weak operation could sporadically fail.
                // We need a strong operation.
                bool weak = false;
                if (__atomic_compare_exchange_n(
                        &_host_worker_contexts[tries].event,
                        &oldval,
                        newval,
                        weak,
                        __ATOMIC_ACQ_REL,
                        __ATOMIC_ACQUIRE))
                {
                    // The pevious value of the event was 0 which means that the
                    // worker was previously sleeping.
                    // Wake it via an ocall.
                    oe_ocall(
                        OE_OCALL_WAKE_HOST_WORKER,
                        (uint64_t)&_host_worker_contexts[tries],
                        NULL);
                }

                return OE_OK;
            }
        }
    }

    result = OE_CONTEXT_SWITCHLESS_OCALL_MISSED;

    return result;
}

/*
**==============================================================================
**
** oe_switchless_call_host_function()
**
**==============================================================================
*/

oe_result_t oe_switchless_call_host_function(
    size_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    return oe_call_host_function_by_table_id(
        OE_UINT64_MAX,
        function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written,
        true /* switchless */);
}
