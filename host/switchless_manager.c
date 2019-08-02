// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "switchless_manager.h"
#include <openenclave/internal/calls.h>
#include "hostthread.h"
#include "sgx/enclave.h"

static void _atomic_compare_exchange_state(
    oe_switchless_state_t* value,
    oe_switchless_state_t* expected,
    oe_switchless_state_t exchange)
{
#ifdef _MSC_VER
    *expected = (oe_switchless_state_t)_InterlockedCompareExchange(
        value, exchange, *expected);
#elif defined __GNUC__
    __atomic_compare_exchange_n(
        value, expected, exchange, 1, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
#endif /* _MSC_VER or __GNUC__ */
} /* _atomic_compare_exchange_state */

static void _atomic_exchange_state(
    oe_switchless_state_t* value,
    oe_switchless_state_t exchange)
{
#ifdef _MSC_VER
    _InterlockedExchange(value, exchange);
#elif defined __GNUC__
    __atomic_exchange_n(value, exchange, __ATOMIC_RELEASE);
#endif /* _MSC_VER or __GNUC__ */
} /* _atomic_exchange_state */

static int _atomic_try_lock(uint32_t* lock)
{
#ifdef _MSC_VER
    return !(uint32_t)_InterlockedCompareExchange(lock, 1, 0);
#elif defined __GNUC__
    uint32_t zero = 0;
    return __atomic_compare_exchange_n(
        lock, &zero, 1, 1, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
#endif /* _MSC_VER or __GNUC__ */
} /* _atomic_try_lock */

typedef struct _enc_worker_start_args
{
    oe_enc_switchless_worker_start_args_t args;
    oe_enclave_t* enclave;
} enc_worker_start_args_t;

static oe_thread_return_t _enclave_worker_thread(oe_thread_arg_t _args)
{
    enc_worker_start_args_t* args = (enc_worker_start_args_t*)_args;

    oe_ecall(
        args->enclave,
        OE_ECALL_LAUNCH_ENCLAVE_WORKER,
        (uint64_t) & (args->args),
        NULL);

    return OE_THREAD_RETURN_VAL;
} /* _enclave_worker_thread */

typedef struct _host_worker_start_args
{
    oe_result_t result;
    oe_enclave_t* enclave;
    uint32_t lock;
} host_worker_start_args_t;

// this function is copy-n-paste from calls.c<core>
static oe_switchless_state_t _get_switchless_state(oe_switchless_t* switchless)
{
    oe_switchless_state_t state;
    state = __atomic_load_n(&(switchless->state), __ATOMIC_ACQUIRE);
    return state;
} /* _get_switchless_state */

typedef enum _loop_state {
    READING_HEADER,
    READING_BUFFER,
    WRITING,
    WAITING_FOR_LOCK,
} loop_state_t;

#include <stdio.h>

static oe_thread_return_t _host_worker_thread(oe_thread_arg_t args_in)
{
    //printf ("<starting host_worker_thread>\n");
    oe_result_t result = OE_FAILURE;
    host_worker_start_args_t* volatile args = (host_worker_start_args_t*)args_in;
    oe_enclave_t* enclave = NULL;
    loop_state_t state = READING_HEADER;
    oe_call_host_function_args_t ocall_header;
    char* buffer = NULL;
    size_t total_size = sizeof (oe_call_host_function_args_t);
    size_t current_size = 0;

    /* args_in will no longer be valid after the lock is released */
    enclave = args->enclave;
    args->result = OE_OK;
    __atomic_exchange_n(&(args->lock), 0, __ATOMIC_RELEASE);

    result = OE_OK;

    /* There are a lot of things that should be considered for the worker
     * thread.
     * * First off, this PoC only supports one host worker thread.  There are
     *   many other considerations that need to be added to support multiple
     *   host worker threads.  I'll try to point them out where they come up.
     * * The host worker thread present a different opportunity since there is
     *   no significant penalty for using a mutex and condition variable in
     *   host.
     * * The host worker thread could be put to sleep.
     * * It would be more effective to put host worker threads to sleep or spin
     *   up more host worker threads in direct proportion to the number of
     *   threads running in the enclave.
     * * If there are multiple host worker threads running, there would need to
     *   be a ring buffer and corresponding lock per thread.
     */
    
    //printf ("<case READING_HEADER>\n");
    while (OE_SWITCHLESS_STATE_STOPPING != _get_switchless_state(
               &(enclave->switchless_manager.switchless)))
    {
        switch (state)
        {
        case READING_HEADER:
        {
            /* read the header to determine how large to make the buffer */
            size_t read =
                oe_lockless_ring_buffer_read(
                    enclave->switchless_manager.switchless.ocall_buffer,
                    ((char*)&ocall_header) + current_size,
                    total_size - current_size);
            current_size += read;
            //if (0 < read)
            //{
            //    printf(" ---- read: %u -- current: %u -- total: %u\n",
            //           (unsigned)read, (unsigned)current_size, (unsigned)total_size);
            //}
            /* has the entire header been read? */
            if (total_size == current_size)
            {
                //printf ("<case READING_BUFFER>\n");
                /* there should be checks here to limit total_size and
                 * check the return value of malloc */
                total_size = ocall_header.input_buffer_size +
                    ocall_header.output_buffer_size;
                current_size = 0;
                buffer = malloc(total_size);
                state = READING_BUFFER;
            }
            break;
        }
        case READING_BUFFER:
        {
            /* read the buffer */
            size_t read =
                oe_lockless_ring_buffer_read(
                    enclave->switchless_manager.switchless.ocall_buffer,
                    buffer + current_size,
                    total_size - current_size);
            current_size += read;
            /* has the entire buffer been read? */
            if (total_size == current_size)
            {
                /* when host_worker_lock == 0, the enclave can read
                 * when host_worker_lock == 1, the host can read */
                /* release the lock */
                __atomic_store_n(
                    &(enclave->switchless_manager.switchless.host_worker_lock),
                    0, __ATOMIC_RELEASE);

                /* set up the buffer pointers */
                ocall_header.input_buffer = buffer;
                ocall_header.output_buffer =
                    buffer + ocall_header.input_buffer_size;
                /* call the handler function */
                ocall_header.result = _handle_call_host_function(
                    (uint64_t)&ocall_header, enclave);
                //printf ("<case WRITING> %s\n", oe_result_str(ocall_header.result));
                state = WRITING;
                current_size = 0;
                if (OE_OK == ocall_header.result)
                {
                    /* return everything */
                    total_size += sizeof(oe_call_host_function_args_t);
                }
                else
                {
                    /* just return the header */
                    total_size = sizeof(oe_call_host_function_args_t);
                    free(buffer);
                    buffer = NULL;
                }
            }
            break;
        }
        case WRITING:
            if (current_size < sizeof(oe_call_host_function_args_t))
            {
                size_t written =
                    oe_lockless_ring_buffer_write(
                        enclave->switchless_manager.switchless.ocall_buffer,
                        ((char*)&ocall_header) + current_size,
                        sizeof(oe_call_host_function_args_t) - current_size);
                current_size += written;
                //printf(" ---- written: %u -- current: %u -- total: %u\n",
                //       (unsigned)written, (unsigned)current_size, (unsigned)total_size);
            }
            else if (current_size < total_size)
            {
                size_t written =
                    oe_lockless_ring_buffer_write(
                        enclave->switchless_manager.switchless.ocall_buffer,
                        buffer + current_size - sizeof(oe_call_host_function_args_t),
                        total_size - current_size);
                //printf(" -- buffer_write %u bytes -- returned %u\n",
                //       (unsigned)(total_size - current_size),
                //       (unsigned)written);
                current_size += written;
                //printf(" ---- written: %u -- current: %u -- total: %u\n",
                //       (unsigned)written, (unsigned)current_size, (unsigned)total_size);
            }
            //else
            //{
            //    printf(".");
            //}
            /* start reading a new ocall when the writing is finished */
            if (current_size == total_size)
            {
                //printf ("<case WAITING_FOR_LOCK>\n");
                state = WAITING_FOR_LOCK;
                free(buffer);
                buffer = NULL;
            }
            break;
        case WAITING_FOR_LOCK:
        {
            /* when host_worker_lock == 0, the enclave can read
             * when host_worker_lock == 1, the host can read */
            if (1 == __atomic_load_n(
                    &(enclave->switchless_manager.switchless.host_worker_lock),
                    __ATOMIC_ACQUIRE))
            {
                //printf("<case READING_HEADER>\n");
                state = READING_HEADER;
                total_size = sizeof(oe_call_host_function_args_t);
                current_size = 0;
            }
            break;
        }
            
        }
    }

    //printf ("<exiting host_worker_thread>\n");
    return OE_THREAD_RETURN_VAL;
} /* _enclave_worker_thread */

void oe_switchless_manager_init(oe_enclave_t* enclave)
{
    enclave->switchless_manager.switchless.state = OE_SWITCHLESS_STATE_STOPPED;
    oe_lockless_queue_init(
        &(enclave->switchless_manager.switchless.ecall_queue));
    enclave->switchless_manager.switchless.ocall_buffer = NULL;
    enclave->switchless_manager.switchless.host_worker_lock = 0;
} /* oe_switchless_manager_init */

static oe_result_t _start_enc_worker_thread(oe_enclave_t* enclave)
{
    oe_result_t result = OE_FAILURE;
    
    enc_worker_start_args_t args = {
        {&(enclave->switchless_manager.switchless), OE_FAILURE, 1}, enclave};
    if (0 == oe_thread_create(
            &(enclave->switchless_manager.enclave_worker),
            _enclave_worker_thread,
            &args))
    {
        /* wait for the thread to get started
         * the new thread calls oe_ecall with
         * OE_ECALL_LAUNCH_ENCLAVE_WORKER which will result in one of two
         * things:
         * 1. things go right and the enclave worker thread loop begins in which
         * case the call does not return
         * 2. the oe_call fails and the call returns the lock in
         * oe_enc_switchless_worker_start_args_t is used to determine which
         * happened
         * if the oe_ecall is successful, it will not return, so in either case
         * the enclave will set the result, and release the lock */
        /* wait for the lock to clear */
        while (!_atomic_try_lock(&(args.args.lock)))
        {
            continue;
        }
        if (OE_OK == args.args.result)
        {
            /* thread creation succeeded */
            result = OE_OK;
        }
    }
    
    return result;
} /* _start_enc_worker_thread */

static oe_result_t _start_host_worker_thread(oe_enclave_t* enclave)
{
    oe_result_t result = OE_FAILURE;
    
    host_worker_start_args_t args = {OE_FAILURE, enclave, 1};
    if (0 == oe_thread_create(
            &(enclave->switchless_manager.host_worker),
            _host_worker_thread,
            &args))
    {
        /* wait for the thread to get started */
        /* wait for the lock to clear */
        while (!_atomic_try_lock(&(args.lock)))
        {
            continue;
        }
        if (OE_OK == args.result)
        {
            /* thread creation succeeded */
            result = OE_OK;
        }
    }

    return result;
} /* _start_host_worker_thread */

oe_result_t oe_switchless_manager_startup(oe_enclave_t* enclave)
{
    size_t const BUFFER_SIZE = 4096;
    oe_result_t result = OE_FAILURE;
    oe_switchless_state_t state = OE_SWITCHLESS_STATE_STOPPED;

    if (NULL == enclave->switchless_manager.switchless.ocall_buffer)
    {
        enclave->switchless_manager.switchless.ocall_buffer =
            (oe_lockless_ring_buffer_t*)malloc(
                sizeof(oe_lockless_ring_buffer_t) + BUFFER_SIZE);
    }
    oe_lockless_ring_buffer_init(
        enclave->switchless_manager.switchless.ocall_buffer, BUFFER_SIZE);

    /* the state should be RUNNING when this method returns
     * only change the state to STARTING if it was STOPPED
     * wait if the state is STARTING or STOPPING */
    while (OE_SWITCHLESS_STATE_STOPPED == state)
    {
        /* test the state and switch to STARTING if it was STOPPED
         * *note* by design this thread is waiting for another thread to change
         * the state so ACQUIRE semantics are need for the read, and RELEASE
         * semantics are required if a write is performed */
        _atomic_compare_exchange_state(
            &(enclave->switchless_manager.switchless.state),
            &state,
            OE_SWITCHLESS_STATE_STARTING);

        /* if the previous state was STOPPED it has been changed to STARTING
         * this thread may now start the switchless_manager */
        if (OE_SWITCHLESS_STATE_STOPPED == state)
        {
            /* start the enclave worker thread */
            result = _start_enc_worker_thread(enclave);

            if (OE_OK == result)
            {
                /* start the host worker thread */
                result = _start_host_worker_thread(enclave);

                if (OE_OK == result)
                {
                    /* everything started correctly now change the state to
                     * running */
                    _atomic_exchange_state(
                        &(enclave->switchless_manager.switchless.state),
                        OE_SWITCHLESS_STATE_RUNNING);
                }
                else
                {
                    /* failed to start the host worker thread so stop the
                     * enclave worker thread and change the state to stopped and
                     * give up */
                    _atomic_exchange_state(
                        &(enclave->switchless_manager.switchless.state),
                        OE_SWITCHLESS_STATE_STOPPING);
                    oe_thread_join(enclave->switchless_manager.enclave_worker);
                    _atomic_exchange_state(
                        &(enclave->switchless_manager.switchless.state),
                        OE_SWITCHLESS_STATE_STOPPED);
                    break;
                }
            }
            else
            {
                /* failed to start the enclave worker thread so change the state
                 * to stopped and give up */
                _atomic_exchange_state(
                    &(enclave->switchless_manager.switchless.state),
                    OE_SWITCHLESS_STATE_STOPPED);
                break;
            }
        }
        else if (OE_SWITCHLESS_STATE_RUNNING == state)
        {
            /* if the state was already RUNNING the loop will exit */
            result = OE_OK;
        }
        else
        {
            /* if the state was STARTING or STOPPING the loop will spin
             * reset the loop control */
            state = OE_SWITCHLESS_STATE_STOPPED;
        }
    }

    return result;
} /* oe_switchless_manager_startup */

void oe_switchless_manager_shutdown(oe_enclave_t* enclave)
{
    oe_switchless_state_t state = OE_SWITCHLESS_STATE_RUNNING;

    /* the state should be STOPPED when this method returns
     * change the state to STOPPING if it was running
     * wait if the state is STARTING or STOPPING */

    while (OE_SWITCHLESS_STATE_RUNNING == state)
    {
        /* test the state and switch to STOPPING if it was RUNNING
         * *note* by design this thread is waiting for another thread to change
         * the state so ACQUIRE semantics are need for the read, and RELEASE
         * semantics are required if a write is performed */

        _atomic_compare_exchange_state(
            &(enclave->switchless_manager.switchless.state),
            &state,
            OE_SWITCHLESS_STATE_STOPPING);

        /* if the previous state was RUNNING it has been changed to STOPPING
         * this thread may now stop the switchless_manager */
        if (OE_SWITCHLESS_STATE_RUNNING == state)
        {
            oe_thread_join(enclave->switchless_manager.enclave_worker);
            oe_thread_join(enclave->switchless_manager.host_worker);

            /* change the state to STOPPED
             * *note* by design, no other thread can change the state while it
             * is STOPPING so RELEASE semantics are all that is needed here */
            _atomic_exchange_state(
                &(enclave->switchless_manager.switchless.state),
                OE_SWITCHLESS_STATE_STOPPED);
        }
        else if (OE_SWITCHLESS_STATE_STOPPED == state)
        {
            /* if the state was already STOPPED the loop will exit */
        }
        else
        {
            /* if the state was STARTING or STOPPING the loop will spin
             * reset the loop control */
            state = OE_SWITCHLESS_STATE_RUNNING;
        }
    }

    if (NULL != enclave->switchless_manager.switchless.ocall_buffer)
    {
        free(enclave->switchless_manager.switchless.ocall_buffer);
        enclave->switchless_manager.switchless.ocall_buffer = NULL;
    }
} /* oe_switchless_manager_shutdown */
