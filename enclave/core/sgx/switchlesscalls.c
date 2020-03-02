// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "switchlesscalls.h"
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/atomic.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include "switchless_t.h"

// The number of host thread workers. Initialized by host through ECALL
static size_t _host_worker_count = 0;

// The array of host worker contexts. Initialized by host through ECALL
static oe_host_worker_context_t* _host_worker_contexts = NULL;

// Flag to denote if switchless calls have already been initialized.
static bool _is_switchless_initialized = false;

static bool _switchless_init_in_progress = false;

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
    bool is_initialized;

    is_initialized =
        __atomic_load_n(&_is_switchless_initialized, __ATOMIC_SEQ_CST);

    return is_initialized;
}

/*
**==============================================================================
**
** oe_init_context_switchless_ecall()
**
** Initialize switchless calls infrastructure. This function call be called only
** once.
**
**==============================================================================
*/
oe_result_t oe_init_context_switchless_ecall(
    oe_host_worker_context_t* host_worker_contexts,
    uint64_t num_host_workers)
{
    oe_result_t result = OE_UNEXPECTED;
    uint64_t contexts_size = 0;

    if (!oe_atomic_compare_and_swap(
            (volatile int64_t*)&_switchless_init_in_progress,
            (int64_t) false,
            (int64_t) true))
    {
        OE_RAISE(OE_BUSY);
    }

    if (oe_is_switchless_initialized())
    {
        OE_RAISE(OE_ALREADY_INITIALIZED);
    }

    contexts_size = sizeof(oe_host_worker_context_t) * num_host_workers;

    // Ensure the contexts are outside of enclave
    if (!oe_is_outside_enclave(host_worker_contexts, contexts_size) ||
        num_host_workers == 0)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* lfence after checks. */
    oe_lfence();

    // Stash host worker information in enclave memory.
    _host_worker_count = num_host_workers;
    _host_worker_contexts = host_worker_contexts;

    __atomic_store_n(&_is_switchless_initialized, true, __ATOMIC_SEQ_CST);

    result = OE_OK;

done:
    __atomic_store_n(&_switchless_init_in_progress, false, __ATOMIC_SEQ_CST);

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
                // making an ocall (oe_wake_switchless_worker_ocall).
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
                    oe_wake_switchless_worker_ocall(
                        &_host_worker_contexts[tries]);
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
