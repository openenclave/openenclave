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

typedef struct _worker_start_args
{
    oe_enc_switchless_worker_start_args_t args;
    oe_enclave_t* enclave;
} worker_start_args_t;

static oe_thread_return_t _enclave_worker_thread(oe_thread_arg_t _args)
{
    worker_start_args_t* args = (worker_start_args_t*)_args;

    oe_ecall(
        args->enclave,
        OE_ECALL_LAUNCH_ENCLAVE_WORKER,
        (uint64_t) & (args->args),
        NULL);

    return OE_THREAD_RETURN_VAL;
} /* _enclave_worker_thread */

void oe_switchless_manager_init(oe_enclave_t* enclave)
{
    enclave->switchless_manager.switchless.state = OE_SWITCHLESS_STATE_STOPPED;
    oe_lockless_queue_init(
        &(enclave->switchless_manager.switchless.ecall_queue));
} /* oe_switchless_manager_init */

oe_result_t oe_switchless_manager_startup(oe_enclave_t* enclave)
{
    oe_result_t result = OE_FAILURE;
    oe_switchless_state_t state = OE_SWITCHLESS_STATE_STOPPED;

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
            worker_start_args_t args = {
                {&(enclave->switchless_manager.switchless), OE_FAILURE, 1},
                enclave};
            if (0 == oe_thread_create(
                         &(enclave->switchless_manager.enclave_worker),
                         _enclave_worker_thread,
                         &args))
            {
                /* wait for the thread to get started
                 * the new thread calls oe_ecall with
                 * OE_ECALL_LAUNCH_ENCLAVE_WORKER which will result in one of
                 * two things:
                 * 1. things go right and the enclave worker thread loop begins
                 *   in which case the call does not return
                 * 2. the oe_call fails and the call returns
                 * the lock in oe_enc_switchless_worker_start_args_t is used to
                 * determine which happened
                 * if the oe_ecall is successful, it will not return, so in
                 * either case the enclave will set the result, and release the
                 * lock */
                /* wait for the lock to clear */
                while (!_atomic_try_lock(&(args.args.lock)))
                {
                    continue;
                }
                if (OE_OK == args.args.result)
                {
                    /* thread creation succeeded
                     * change the state to RUNNING
                     * *note* by design, no other thread can change the state
                     * while it is STARTING so RELEASE semantics are all that is
                     * needed here */
                    _atomic_exchange_state(
                        &(enclave->switchless_manager.switchless.state),
                        OE_SWITCHLESS_STATE_RUNNING);
                    result = OE_OK;
                }
                else
                {
                    /* thread creation failed
                     * change the state to STOPPED and exit the loop
                     * *note* by design, no other thread can change the state
                     * while it is STARTING so RELEASE semantics are all that is
                     * needed here */
                    _atomic_exchange_state(
                        &(enclave->switchless_manager.switchless.state),
                        OE_SWITCHLESS_STATE_STOPPED);
                    break;
                }
            }
            else
            {
                /* thread creation failed
                 * change the state to STOPPED and exit the loop
                 * *note* by design, no other thread can change the state while
                 * it is STARTING so RELEASE semantics are all that is needed
                 * here */
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
} /* oe_switchless_manager_shutdown */
