// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/atomic.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/switchless.h>
#include <openenclave/internal/utils.h>
#include "../calls.h"
#include "../hostthread.h"
#include "enclave.h"
#include "platform_u.h"

/**
 * Number of iterations an ocall worker thread would spin before going to sleep
 */
#define OE_HOST_WORKER_SPIN_COUNT_THRESHOLD (4096U)

/**
 * Number of iterations an ecall worker thread would spin before going to sleep
 */
#define OE_ENCLAVE_WORKER_SPIN_COUNT_THRESHOLD (4096U)

/**
 * Declare the prototypes of the following functions to avoid missing-prototypes
 * warning.
 */
OE_UNUSED_FUNC oe_result_t _oe_sgx_init_context_switchless_ecall(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    oe_host_worker_context_t* host_worker_contexts,
    uint64_t num_host_workers);
OE_UNUSED_FUNC oe_result_t _oe_sgx_switchless_enclave_worker_thread_ecall(
    oe_enclave_t* enclave,
    oe_enclave_worker_context_t* context);

/**
 * Make the following ECALLs weak to support the system EDL opt-in.
 * When the user does not opt into (import) the EDL, the linker will pick
 * the following default implementations. If the user opts into the EDL,
 * the implementions (which are also weak) in the oeedger8r-generated code will
 * be used. This behavior is guaranteed by the linker; i.e., the linker will
 * pick the symbols defined in the object before those in the library.
 */
oe_result_t _oe_sgx_init_context_switchless_ecall(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    oe_host_worker_context_t* host_worker_contexts,
    uint64_t num_host_workers)
{
    OE_UNUSED(enclave);
    OE_UNUSED(host_worker_contexts);
    OE_UNUSED(num_host_workers);

    if (_retval)
        *_retval = OE_UNSUPPORTED;

    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(
    _oe_sgx_init_context_switchless_ecall,
    oe_sgx_init_context_switchless_ecall);

oe_result_t _oe_sgx_switchless_enclave_worker_thread_ecall(
    oe_enclave_t* enclave,
    oe_enclave_worker_context_t* context)
{
    OE_UNUSED(enclave);
    OE_UNUSED(context);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(
    _oe_sgx_switchless_enclave_worker_thread_ecall,
    oe_sgx_switchless_enclave_worker_thread_ecall);

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
                (uint64_t)local_call_arg, context->enc);

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

            /* Yield CPU */
            oe_yield_cpu();
        }
    }
    return NULL;
}

void oe_sgx_sleep_switchless_worker_ocall(oe_enclave_worker_context_t* context)
{
    // Wait for messages.
    oe_enclave_worker_wait(context);
}

/*
** The thread function that handles switchless ecalls
**
*/
static void* _switchless_ecall_worker(void* arg)
{
    oe_enclave_worker_context_t* context = (oe_enclave_worker_context_t*)arg;

    // Enter enclave to process ecall messages.
    if (oe_sgx_switchless_enclave_worker_thread_ecall(context->enc, context) !=
        OE_OK)
    {
        OE_TRACE_ERROR("Switchless enclave worker thread failed\n");
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
    for (size_t i = 0; i < manager->num_enclave_workers; i++)
    {
        manager->enclave_worker_contexts[i].is_stopping = true;
        oe_enclave_worker_wake(&manager->enclave_worker_contexts[i]);
    }

    for (size_t i = 0; i < manager->num_host_workers; i++)
    {
        if (manager->host_worker_threads[i] != (oe_thread_t)NULL)
            if (oe_thread_join(manager->host_worker_threads[i]))
                OE_RAISE(OE_THREAD_JOIN_ERROR);
    }

    for (size_t i = 0; i < manager->num_enclave_workers; i++)
    {
        if (manager->enclave_worker_threads[i] != (oe_thread_t)NULL)
            if (oe_thread_join(manager->enclave_worker_threads[i]))
                OE_RAISE(OE_THREAD_JOIN_ERROR);
    }

    result = OE_OK;
done:
    return result;
}

oe_result_t oe_start_switchless_manager(
    oe_enclave_t* enclave,
    size_t num_host_workers,
    size_t num_enclave_workers)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_result_t result_out = 0;
    oe_switchless_call_manager_t* manager = NULL;
    oe_host_worker_context_t* host_contexts = NULL;
    oe_thread_t* host_threads = NULL;
    oe_enclave_worker_context_t* enclave_contexts = NULL;
    oe_thread_t* enclave_threads = NULL;

    if (enclave == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (enclave->switchless_manager != NULL)
        OE_RAISE(OE_UNEXPECTED);

    if (num_host_workers == 0 && num_enclave_workers == 0)
        OE_RAISE(OE_UNEXPECTED);

    // Limit the number of workers to the number of thread bindings
    // because the maximum parallelism is dictated by the latter for
    // synchronous ocalls. We may need to revisit this for asynchronous
    // calls later.
    if (num_host_workers > enclave->num_bindings)
        num_host_workers = (uint32_t)enclave->num_bindings;

    if (num_enclave_workers > enclave->num_bindings)
        num_enclave_workers = (uint32_t)enclave->num_bindings;

    // Allocate memory for the manager and its arrays
    manager = calloc(1, sizeof(oe_switchless_call_manager_t));
    if (manager == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    host_contexts = calloc(num_host_workers, sizeof(oe_host_worker_context_t));
    if (host_contexts == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    host_threads = calloc(num_host_workers, sizeof(oe_thread_t));
    if (host_threads == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    enclave_contexts =
        calloc(num_enclave_workers, sizeof(oe_enclave_worker_context_t));
    if (enclave_contexts == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    enclave_threads = calloc(num_enclave_workers, sizeof(oe_thread_t));
    if (enclave_threads == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    manager->num_host_workers = num_host_workers;
    manager->host_worker_contexts = host_contexts;
    manager->host_worker_threads = host_threads;
    manager->num_enclave_workers = num_enclave_workers;
    manager->enclave_worker_contexts = enclave_contexts;
    manager->enclave_worker_threads = enclave_threads;

    // Start the host worker threads, and assign each one a private context.
    for (size_t i = 0; i < num_host_workers; i++)
    {
        OE_TRACE_INFO("Creating switchless host worker thread %d\n", (int)i);
        manager->host_worker_contexts[i].enc = enclave;
        if (oe_thread_create(
                &manager->host_worker_threads[i],
                _switchless_ocall_worker,
                &manager->host_worker_contexts[i]) != 0)
        {
            OE_RAISE(OE_THREAD_CREATE_ERROR);
        }
    }

    // Inform the enclave about the switchless manager through an ECALL
    if (num_host_workers > 0)
    {
        OE_CHECK(oe_sgx_init_context_switchless_ecall(
            enclave,
            &result_out,
            manager->host_worker_contexts,
            manager->num_host_workers));
        OE_CHECK(result_out);
    }

    // Start the enclave worker threads, and assign each one a private context.
    // ecall worker threads are initialized after the regular ecall above to
    // oe_sgx_init_context_switchless_ecall is complete.
    for (size_t i = 0; i < num_enclave_workers; i++)
    {
        OE_TRACE_INFO("Creating switchless enclave worker thread %d\n", (int)i);
        manager->enclave_worker_contexts[i].enc = enclave;
        manager->enclave_worker_contexts[i].spin_count_threshold =
            OE_ENCLAVE_WORKER_SPIN_COUNT_THRESHOLD;
        if (oe_thread_create(
                &manager->enclave_worker_threads[i],
                _switchless_ecall_worker,
                &manager->enclave_worker_contexts[i]) != 0)
        {
            OE_RAISE(OE_THREAD_CREATE_ERROR);
        }

        // Wait until the enclave worker thread has started.
        // If so, spin_count and/or total_spin_count will be non zero.
        // This ensures that each ecall worker thread has a dedicated tcs.
        volatile oe_enclave_worker_context_t* ctx =
            &manager->enclave_worker_contexts[i];
        while (!ctx->spin_count && !ctx->total_spin_count)
        {
            oe_yield_cpu();
        }
    }

    // Each enclave has at most one switchless manager.
    enclave->switchless_manager = manager;

    result = OE_OK;

done:
    if (result == OE_UNSUPPORTED)
        OE_TRACE_WARNING(
            "Switchless call is not supported. To enable, please add \n\n"
            "from \"openenclave/edl/sgx/switchless.edl\" import *;\n\n"
            "in the edl file.\n");

    if (result != OE_OK)
    {
        oe_stop_switchless_manager(enclave);
    }

    return result;
}

oe_result_t oe_stop_switchless_manager(oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_switchless_call_manager_t* manager = NULL;
    if (enclave != NULL && enclave->switchless_manager != NULL)
    {
        OE_CHECK(oe_stop_worker_threads(enclave->switchless_manager));

        manager = enclave->switchless_manager;
        enclave->switchless_manager = NULL;

        // Free all allocated buffers.
        if (manager->host_worker_contexts != NULL)
            free(manager->host_worker_contexts);
        if (manager->host_worker_threads != NULL)
            free(manager->host_worker_threads);
        if (manager->enclave_worker_contexts != NULL)
            free(manager->enclave_worker_contexts);
        if (manager->enclave_worker_threads != NULL)
            free(manager->enclave_worker_threads);
        free(manager);
    }
    result = OE_OK;
done:
    return result;
}

void oe_sgx_wake_switchless_worker_ocall(oe_host_worker_context_t* context)
{
    oe_host_worker_wake(context);
}

/*
**==============================================================================
**
** oe_switchless_call_enclave_function()
**
** Switchlessly call the enclave function specified by the given function-id in
** the function table.
**
**==============================================================================
*/
oe_result_t oe_switchless_call_enclave_function(
    oe_enclave_t* enclave,
    uint32_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    oe_result_t result = OE_UNEXPECTED;
    bool switchless_call_posted = false;
    oe_call_enclave_function_args_t args;
    oe_switchless_call_manager_t* manager = enclave->switchless_manager;
    oe_enclave_worker_context_t* contexts = manager->enclave_worker_contexts;
    size_t tries = 0;

    /* Reject invalid parameters */
    if (!enclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize the call_enclave_args structure */
    {
        args.function_id = function_id;
        args.input_buffer = input_buffer;
        args.input_buffer_size = input_buffer_size;
        args.output_buffer = output_buffer;
        args.output_buffer_size = output_buffer_size;
        args.output_bytes_written = 0;
        args.result = OE_UNEXPECTED;
    }

    // Schedule the switchless call.
    OE_ATOMIC_MEMORY_BARRIER_RELEASE();
    args.result = __OE_RESULT_MAX; // Means the call hasn't been processed.

    // Cycle through the worker contexts until we find a free worker.
    tries = manager->num_enclave_workers;
    while (tries--)
    {
        // Check if the worker's slot is free.
        if (contexts[tries].call_arg == NULL)
        {
            // Try to atomically grab the slot by placing args in the slot.
            // If the atomic operation was successful, then the worker thread
            // will execute this switchless ecall. If the atomic operation
            // failed, this means that the slot was grabbed by another
            // switchless ocall and therefore, we must scan for another worker
            // thread with a free slot.
            if (oe_atomic_compare_and_swap_ptr(
                    (void* volatile*)&contexts[tries].call_arg, NULL, &args))
            {
                // The worker thread has been marked to execute this switchless
                // call. Determine if it needs to be woken up or not.
                //
                // If event is 0, it means that it has gone to sleep. Wake it by
                // making an ocall (oe_sgx_wake_switchless_worker_ocall).
                // Note: it is important to use an atomic cas operation to set
                // the value to 1 before making the ocall. Setting the value to
                // 1 prevents the host worker from simulataneously going to
                // sleep. If instead, just a compare operation is used to
                // determine if the host thread is sleeping or not, the host
                // thread could go to sleep after the enclave has determined
                // that the host is not sleeping, causing a deadlock.
                //
                // If event is 1, that indicates a pending wake notification.
                uint32_t oldval = 0;
                uint32_t newval = 1;
                // Weak operation could sporadically fail.
                // We need a strong operation.
                if (oe_atomic_compare_and_swap_32(
                        (uint32_t*)&contexts[tries].event, oldval, newval))
                {
                    // The pevious value of the event was 0 which means that the
                    // worker was previously sleeping.
                    // Wake it.
                    oe_enclave_worker_wake(&contexts[tries]);
                }

                switchless_call_posted = true;
                // Wait for the  call to complete.
                while (true)
                {
                    if (oe_atomic_load((uint64_t*)&contexts[tries].call_arg) !=
                        (uint64_t)&args)
                        break;

                    /* Yield CPU */
                    oe_yield_cpu();
                }
                break;
            }
        }
    }

    if (!switchless_call_posted)
    {
        // Dispatch as normal ecall.
        OE_CHECK(oe_ecall(
            enclave, OE_ECALL_CALL_ENCLAVE_FUNCTION, (uint64_t)&args, NULL));
    }

    /* Check the result */
    OE_CHECK(args.result);

    *output_bytes_written = args.output_bytes_written;
    result = OE_OK;

done:
    return result;
}
