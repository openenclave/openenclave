// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/td.h>
#include <openenclave/internal/tests.h>
#include "thread_interrupt_t.h"

#include <signal.h>
#include <stdio.h>

#define REPEAT_TIMES 10

static int _signal_list[] =
    {SIGHUP, SIGABRT, SIGALRM, SIGPIPE, SIGPOLL, SIGUSR1, SIGUSR2};

#define SIGNAL_NUMBER (sizeof(_signal_list) / sizeof(_signal_list[0]))

static int _current_signal;

typedef struct _thread_info_nonblocking_t
{
    int lock;
    int tid;
    oe_sgx_td_t* td;
} thread_info_t;

static thread_info_t _thread_info_nonblocking;
static thread_info_t _thread_info_blocking;
static volatile int _handler_entered;

uint64_t thread_interrupt_handler(oe_exception_record_t* exception_record)
{
    int self_tid = 0;

    _handler_entered = 1;

    OE_TEST(exception_record->code == OE_EXCEPTION_UNKNOWN);

    OE_TEST(exception_record->host_signal_number == _current_signal);

    host_get_tid(&self_tid);
    OE_TEST(_thread_info_nonblocking.tid == self_tid);

    printf("(tid=%d) thread is interrupted...\n", self_tid);

    OE_TEST(
        _thread_info_nonblocking.td->state ==
        OE_TD_STATE_SECOND_LEVEL_EXCEPTION_HANDLING);

    __atomic_store_n(&_thread_info_nonblocking.lock, 2, __ATOMIC_RELEASE);

    return OE_EXCEPTION_CONTINUE_EXECUTION;
}

void enc_run_thread_nonblocking(int tid)
{
    oe_result_t result = OE_OK;
    int self_tid = 0;
    host_get_tid(&self_tid);

    OE_TEST(tid == self_tid);

    printf("(tid=%d) non-blocking thread is running...\n", self_tid);

    OE_CHECK(
        oe_add_vectored_exception_handler(false, thread_interrupt_handler));

    _thread_info_nonblocking.tid = tid;
    _thread_info_nonblocking.td = oe_sgx_get_td();

    // Validate the default state
    OE_TEST(_thread_info_nonblocking.td->state == OE_TD_STATE_RUNNING);

    // Invoke the internal API to unmask host signals
    oe_sgx_td_unmask_host_signal(_thread_info_nonblocking.td);

    // Ensure the order of setting the lock
    asm volatile("" ::: "memory");

    __atomic_store_n(&_thread_info_nonblocking.lock, 1, __ATOMIC_RELEASE);

    // Test receiving different signals
    for (size_t i = 0; i < SIGNAL_NUMBER; i++)
    {
        while (__atomic_load_n(
                   &_thread_info_nonblocking.lock, __ATOMIC_ACQUIRE) != 2)
        {
            asm volatile("pause" ::: "memory");
        }

        // Validate the state after the interrupt
        OE_TEST(_thread_info_nonblocking.td->state == OE_TD_STATE_RUNNING);

        // Ensure the order of setting the lock
        asm volatile("" ::: "memory");

        __atomic_store_n(&_thread_info_nonblocking.lock, 3, __ATOMIC_RELEASE);
    }

    // Test unregistering signals
    for (size_t i = 0; i < SIGNAL_NUMBER; i++)
    {
        OE_TEST(oe_sgx_td_unregister_host_signal(
            _thread_info_nonblocking.td, _signal_list[i]));
    }
    __atomic_store_n(&_thread_info_nonblocking.lock, 4, __ATOMIC_RELEASE);

    // Test receiving the same signal multiple times
    for (size_t i = 0; i < REPEAT_TIMES; i++)
    {
        while (__atomic_load_n(
                   &_thread_info_nonblocking.lock, __ATOMIC_ACQUIRE) != 2)
        {
            asm volatile("pause" ::: "memory");
        }

        // Validate the state after the interrupt
        OE_TEST(_thread_info_nonblocking.td->state == OE_TD_STATE_RUNNING);

        // Ensure the order of setting the lock
        asm volatile("" ::: "memory");

        __atomic_store_n(&_thread_info_nonblocking.lock, 3, __ATOMIC_RELEASE);
    }

    printf("(tid=%d) non-blocking thread is exiting...\n", self_tid);

done:
    return;
}

void enc_thread_interrupt_nonblocking(void)
{
    oe_result_t result;
    int tid = 0;

    host_get_tid(&tid);
    OE_TEST(tid != 0);

    // Test interrupting a non-blocking thread
    printf("(tid=%d) Create a non-blocking thread...\n", tid);

    result = host_create_thread(0 /* blocking */);
    if (result != OE_OK)
        return;

    while (__atomic_load_n(&_thread_info_nonblocking.lock, __ATOMIC_ACQUIRE) !=
           1)
    {
        asm volatile("pause" ::: "memory");
    }

    OE_TEST(_thread_info_nonblocking.tid != 0);

    host_sleep_msec(30);

    // Sending different signals
    for (size_t i = 0; i < SIGNAL_NUMBER; i++)
    {
        _current_signal = _signal_list[i];

        // Signal registration
        OE_TEST(
            oe_sgx_td_register_host_signal(
                _thread_info_nonblocking.td, _current_signal) == true);

        printf(
            "(tid=%d) Sending interrupt (%d) to (td=0x%lx, tid=%d)...\n",
            tid,
            _current_signal,
            (uint64_t)_thread_info_nonblocking.td,
            _thread_info_nonblocking.tid);

        host_send_interrupt(_thread_info_nonblocking.tid, _current_signal);

        while (__atomic_load_n(
                   &_thread_info_nonblocking.lock, __ATOMIC_ACQUIRE) != 3)
        {
            asm volatile("pause" ::: "memory");
        }

        host_sleep_msec(30);
    }

    while (__atomic_load_n(&_thread_info_nonblocking.lock, __ATOMIC_ACQUIRE) !=
           4)
    {
        asm volatile("pause" ::: "memory");
    }

    // Expect the signals are unregistered
    for (size_t i = 0; i < SIGNAL_NUMBER; i++)
    {
        OE_TEST(!oe_sgx_td_host_signal_registered(
            _thread_info_nonblocking.td, _signal_list[i]));
    }

    host_sleep_msec(30);

    _current_signal = SIGUSR1;

    // Register SIGUSR1 again
    OE_TEST(
        oe_sgx_td_register_host_signal(
            _thread_info_nonblocking.td, _current_signal) == true);

    // Sending the same signal multiple times
    for (size_t i = 0; i < REPEAT_TIMES; i++)
    {
        printf(
            "(tid=%d) Sending interrupt (%d) to (td=0x%lx, tid=%d)...\n",
            tid,
            _current_signal,
            (uint64_t)_thread_info_nonblocking.td,
            _thread_info_nonblocking.tid);

        host_send_interrupt(_thread_info_nonblocking.tid, _current_signal);

        while (__atomic_load_n(
                   &_thread_info_nonblocking.lock, __ATOMIC_ACQUIRE) != 3)
        {
            asm volatile("pause" ::: "memory");
        }

        host_sleep_msec(30);
    }

    host_join_thread();
}

uint64_t thread_terminate_handler(oe_exception_record_t* exception_record)
{
    int self_tid = 0;

    OE_TEST(exception_record->code == OE_EXCEPTION_UNKNOWN);

    host_get_tid(&self_tid);
    OE_TEST(_thread_info_blocking.tid == self_tid);

    printf("(tid=%d) thread is interrupted...\n", self_tid);

    OE_TEST(
        _thread_info_blocking.td->state ==
        OE_TD_STATE_SECOND_LEVEL_EXCEPTION_HANDLING);

    __atomic_store_n(&_thread_info_blocking.lock, 2, __ATOMIC_RELEASE);

    return OE_EXCEPTION_CONTINUE_EXECUTION;
}

void enc_run_thread_blocking(int tid)
{
    oe_result_t result = OE_OK;
    int self_tid = 0;
    host_get_tid(&self_tid);

    OE_TEST(tid == self_tid);
    printf("(tid=%d) blocking thread is running...\n", self_tid);

    OE_CHECK(
        oe_add_vectored_exception_handler(false, thread_terminate_handler));

    _thread_info_blocking.tid = tid;
    _thread_info_blocking.td = oe_sgx_get_td();

    // Validate the default state
    OE_TEST(_thread_info_blocking.td->state == OE_TD_STATE_RUNNING);

    // Mask host signals (the default behavior)
    oe_sgx_td_mask_host_signal(_thread_info_blocking.td);

    // Ensure the order of setting the lock
    asm volatile("" ::: "memory");

    __atomic_store_n(&_thread_info_blocking.lock, 1, __ATOMIC_RELEASE);

    while (__atomic_load_n(&_thread_info_blocking.lock, __ATOMIC_ACQUIRE) != 2)
    {
        asm volatile("pause" ::: "memory");
    }

    printf("(tid=%d) blocking thread is exiting...\n", self_tid);
done:
    return;
}

void enc_thread_interrupt_blocking(int* ret)
{
    oe_result_t result;
    int tid = 0;
    int retry = 0;

    host_get_tid(&tid);
    OE_TEST(tid != 0);

    // Test interrupting a blocking thread
    printf("(tid=%d) Create a blocking thread...\n", tid);
    result = host_create_thread(1 /* blocking */);
    if (result != OE_OK)
        return;

    while (!_thread_info_blocking.lock)
    {
        asm volatile("pause" ::: "memory");
    }

    OE_TEST(_thread_info_blocking.tid != 0);

    host_sleep_msec(30);

    _handler_entered = 0;
    while (!_handler_entered)
    {
        if (oe_sgx_td_register_host_signal(_thread_info_blocking.td, SIGUSR1) !=
            true)
            break;

        printf(
            "(tid=%d) Sending registered signal (SIGUSR1) to (td=0x%lx, "
            "tid=%d)...%d\n",
            tid,
            (uint64_t)_thread_info_blocking.td,
            _thread_info_blocking.tid,
            ++retry);

        if (_thread_info_blocking.td->state != OE_TD_STATE_RUNNING)
            break;

        host_send_interrupt(_thread_info_blocking.tid, SIGUSR1);

        if (retry == 10)
        {
            printf(
                "Unable to interrrupt (tid=%d) as expected\n",
                _thread_info_blocking.tid);
            break;
        }

        host_sleep_msec(30);
    }

    if (retry != 10)
        goto done;

    retry = 0;
    _handler_entered = 0;

    // The oe_sgx_td_unmask_host_signal API is usually expected to be used
    // by the thread itself. Use here for testing purposes.
    oe_sgx_td_unmask_host_signal(_thread_info_blocking.td);

    while (!_handler_entered)
    {
        printf(
            "(tid=%d) Sending unregistered signal (SIGUSR2) to (td=0x%lx, "
            "tid=%d)...%d\n",
            tid,
            (uint64_t)_thread_info_blocking.td,
            _thread_info_blocking.tid,
            ++retry);

        if (_thread_info_blocking.td->state != OE_TD_STATE_RUNNING)
            break;

        host_send_interrupt(_thread_info_blocking.tid, SIGUSR2);

        if (retry == 10)
        {
            printf(
                "Unable to interrrupt (tid=%d) as expected\n",
                _thread_info_blocking.tid);
            break;
        }

        host_sleep_msec(30);
    }

    if (retry != 10)
        goto done;

    *ret = 1;

done:
    /* unblock and shutdown the thread */
    OE_TEST(
        oe_sgx_td_register_host_signal(_thread_info_blocking.td, SIGUSR2) ==
        true);

    printf(
        "(tid=%d) Shutting down (td=0x%lx, "
        "tid=%d)\n",
        tid,
        (uint64_t)_thread_info_blocking.td,
        _thread_info_blocking.tid);

    host_send_interrupt(_thread_info_blocking.tid, SIGUSR2);

    host_join_thread();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
