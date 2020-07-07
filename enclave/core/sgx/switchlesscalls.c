// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "switchlesscalls.h"
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/atomic.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include "arena.h"
#include "handle_ecall.h"
#include "platform_t.h"

// The number of host thread workers. Initialized by host through ECALL
static size_t _host_worker_count = 0;

// The array of host worker contexts. Initialized by host through ECALL
static oe_host_worker_context_t* _host_worker_contexts = NULL;

// Flag to denote if switchless calls have already been initialized.
static bool _is_switchless_initialized = false;

/* Flag to denote if switchless init function is already in progress
 * _switchless_init_in_progress is defined as int64_t and not bool because
 * we use oe_atomic_compare_and_swap() to manipulate its value. It only takes
 * int64_t* unlike the type-generic built-in atomics
 * __atomic_load_n()/__atomic_save_n(), so if _switchless_init_in_progress is
 * not defined as int64_t, we would need to type-pun through an incompatible
 * type which results in undefined behavior per the C spec.
 * */
static int64_t _switchless_init_in_progress = 0;

#if !defined(OE_USE_BUILTIN_EDL)
/**
 * Declare the prototypes of the following functions to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_sgx_wake_switchless_worker_ocall(
    oe_host_worker_context_t* context);
oe_result_t _oe_sgx_sleep_switchless_worker_ocall(
    oe_enclave_worker_context_t* context);

/**
 * Make the following OCALLs weak to support the system EDL opt-in.
 * When the user does not opt into (import) the EDL, the linker will pick
 * the following default implementations. If the user opts into the EDL,
 * the implementations (which are strong) in the oeedger8r-generated code will
 * be used.
 */
oe_result_t _oe_sgx_wake_switchless_worker_ocall(
    oe_host_worker_context_t* context)
{
    OE_UNUSED(context);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(
    _oe_sgx_wake_switchless_worker_ocall,
    oe_sgx_wake_switchless_worker_ocall);

oe_result_t _oe_sgx_sleep_switchless_worker_ocall(
    oe_enclave_worker_context_t* context)
{
    OE_UNUSED(context);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(
    _oe_sgx_sleep_switchless_worker_ocall,
    oe_sgx_sleep_switchless_worker_ocall);

#endif

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
** oe_sgx_init_context_switchless_ecall()
**
** Initialize switchless calls infrastructure. This function call be called only
** once.
**
**==============================================================================
*/
oe_result_t oe_sgx_init_context_switchless_ecall(
    oe_host_worker_context_t* host_worker_contexts,
    uint64_t num_host_workers)
{
    oe_result_t result = OE_UNEXPECTED;
    uint64_t contexts_size = 0;

    if (!oe_atomic_compare_and_swap(
            &_switchless_init_in_progress, (int64_t) false, (int64_t) true))
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
                    oe_sgx_wake_switchless_worker_ocall(
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

void oe_sgx_switchless_enclave_worker_thread_ecall(
    oe_enclave_worker_context_t* context)
{
    // Ensure that the context lies in host memory.
    if (!oe_is_outside_enclave(context, sizeof(*context)))
        return;

    // Prevent speculative execution.
    oe_lfence();

    const uint64_t spin_count_threshold = context->spin_count_threshold;
    while (!context->is_stopping)
    {
        volatile oe_call_enclave_function_args_t* local_call_arg = NULL;
        if ((local_call_arg = context->call_arg) != NULL)
        {
            // Handle the switchless call, but do not clear the slot yet. Since
            // the slot is not empty, any new incoming switchless call request
            // will be scheduled in another available work thread and get
            // handled immediately.
            oe_handle_call_enclave_function((uint64_t)local_call_arg);

            // After handling the switchless call, mark this worker thread
            // as free by clearing the slot.
            OE_ATOMIC_MEMORY_BARRIER_RELEASE();
            context->call_arg = NULL;

            // Reset spin count for next message.
            context->total_spin_count += context->spin_count;
            context->spin_count = 0;
        }
        else
        {
            // If there is no message, increment spin count until threshold is
            // reached.
            if (++context->spin_count >= spin_count_threshold)
            {
                // Reset spin count and return to host to sleep.
                context->total_spin_count += context->spin_count;
                context->spin_count = 0;

                // Make an ocall to sleep until messages arrive.
                oe_sgx_sleep_switchless_worker_ocall(context);
            }

            // In Release builds, the following pause has been observed to be
            // essential. Without it, the worker thread seems to hog the CPU,
            // preventing host threads from posting switchless ecall messages.
            asm volatile("pause");
        }
    }
}

// Function used by oeedger8r for allocating switchless ocall buffers.
// Preallocate a pool of shared memory per thread for switchless ocalls
// and then allocate memory from that pool. Since OE does not support
// reentrant ecalls in the same thread, there can at most be one ecall
// and one ocall active in a thread. Although an enclave function can
// make multiple OCALLs, the OCALLs are serialized. So the allocation
// for one OCALL doesn't interfere with the allocation for the next OCALL.
// A stack-based allocation scheme is the most efficient in this case.
void* oe_allocate_switchless_ocall_buffer(size_t size)
{
    return oe_arena_malloc(size);
}

// Function used by oeedger8r for freeing ocall buffers.
void oe_free_switchless_ocall_buffer(void* buffer)
{
    OE_UNUSED(buffer);
    oe_arena_free_all();
}
