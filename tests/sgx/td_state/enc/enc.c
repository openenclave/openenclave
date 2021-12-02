// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/jump.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/td.h>
#include <openenclave/internal/tests.h>
#include "td_state_t.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct _thread_info_t
{
    int tid;
    oe_sgx_td_t* td;
} thread_info_t;

static thread_info_t _thread_info;
static volatile int _handler_done;
static volatile int* _host_lock_state;

static thread_info_t _thread_handler_no_return_info;
static oe_jmpbuf_t jump_buffer;

static void cpuid(
    unsigned int leaf,
    unsigned int subleaf,
    unsigned int* eax,
    unsigned int* ebx,
    unsigned int* ecx,
    unsigned int* edx)
{
    asm volatile("cpuid"
                 // CPU id instruction returns values in the following registers
                 : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                 // __leaf is passed in eax (0) and __subleaf in ecx (2)
                 : "0"(leaf), "2"(subleaf));
}

// This function will generate the divide by zero function.
// The handler will catch this exception and fix it, and continue execute.
// It will return 0 if success.
static int divide_by_zero_exception_function(void)
{
    // Making ret, f and d volatile to prevent optimization
    volatile int ret = 1;
    volatile float f = 0;
    volatile double d = 0;

    f = 0.31f;
    d = 0.32;

    // Using inline assembly for idiv to prevent it being optimized out
    // completely. Specify edi as the used register to ensure that 32-bit
    // division is done. 64-bit division generates a 3 byte instruction rather
    // than 2 bytes.
    register int edi __asm__("edi") = 0;
    asm volatile("idiv %1"
                 : "=a"(ret)
                 : "r"(edi) // Divisor of 0 is hard-coded
                 : "%1",
                   "cc"); // cc indicates that flags will be clobbered by ASM

    // Check if the float registers are recovered correctly after the exception
    // is handled.
    if (f < 0.309 || f > 0.321 || d < 0.319 || d > 0.321)
    {
        return -1;
    }

    return 0;
}

static uint64_t td_state_handler(oe_exception_record_t* exception_record)
{
    if (exception_record->code == OE_EXCEPTION_UNKNOWN)
    {
        int self_tid = 0;

        if (_handler_done)
        {
            printf("Unexpected interrupt...\n");
            return OE_EXCEPTION_ABORT_EXECUTION;
        }

        OE_TEST(exception_record->host_signal_number == SIGUSR1);

        // Expect the td->host_signal to be SIGUSR1
        OE_TEST(_thread_info.td->host_signal == SIGUSR1);

        // Expect the state to be OE_TD_STATE_SECOND_LEVEL_EXCEPTION_HANDLING
        OE_EXPECT(
            _thread_info.td->state,
            OE_TD_STATE_SECOND_LEVEL_EXCEPTION_HANDLING);

        // Expect interrupted flag is set
        OE_TEST(oe_sgx_td_is_handling_host_signal(_thread_info.td));

        // Expect the signal is registered
        OE_TEST(oe_sgx_td_host_signal_registered(_thread_info.td, SIGUSR1));

        OE_TEST(exception_record->code == OE_EXCEPTION_UNKNOWN);

        host_get_tid(&self_tid);
        OE_TEST(_thread_info.tid == self_tid);

        printf("(tid=%d) thread is interrupted...\n", self_tid);

        // Expect the state to be persisted after ocall(s)
        OE_EXPECT(
            _thread_info.td->state,
            OE_TD_STATE_SECOND_LEVEL_EXCEPTION_HANDLING);

        {
            uint32_t a, b, c, d;
            cpuid(1, 0, &a, &b, &c, &d);
        }

        printf("(tid=%d) thread emulating cpuid...done\n", self_tid);

        // Expect the state to be persisted after an illegal instruction
        // emulation
        OE_EXPECT(
            _thread_info.td->state,
            OE_TD_STATE_SECOND_LEVEL_EXCEPTION_HANDLING);

        // Expect the flag is persisted
        OE_TEST(oe_sgx_td_is_handling_host_signal(_thread_info.td));

        divide_by_zero_exception_function();

        printf("(tid=%d) thread handling div 0...done\n", self_tid);

        // Expect the state to be
        // OE_TD_STATE_SECOND_LEVEL_EXCEPTION_HANDLING after a nested exception
        OE_EXPECT(
            _thread_info.td->state,
            OE_TD_STATE_SECOND_LEVEL_EXCEPTION_HANDLING);

        // Expect the flag is persisted after a nested exception
        OE_TEST(oe_sgx_td_is_handling_host_signal(_thread_info.td));

        OE_TEST(
            oe_sgx_td_unregister_host_signal(_thread_info.td, SIGUSR1) == true);

        __atomic_store_n(_host_lock_state, 2, __ATOMIC_RELEASE);

        _handler_done = 1;

        return OE_EXCEPTION_CONTINUE_EXECUTION;
    }
    else if (exception_record->code == OE_EXCEPTION_DIVIDE_BY_ZERO)
    {
        int self_tid = 0;

        OE_EXPECT(
            _thread_info.td->state,
            OE_TD_STATE_SECOND_LEVEL_EXCEPTION_HANDLING);

        host_get_tid(&self_tid);
        OE_TEST(_thread_info.tid == self_tid);

        // Skip the idiv instruction - 2 is tied to the size of the idiv
        // instruction and can change with a different compiler/build.
        // Minimizing this with the use of the inline assembly for integer
        // division
        exception_record->context->rip += 2;
        return OE_EXCEPTION_CONTINUE_EXECUTION;
    }
    else
    {
        return OE_EXCEPTION_ABORT_EXECUTION;
    }
}

void enc_run_thread(int tid)
{
    oe_result_t result = OE_OK;
    int self_tid = 0;

    _thread_info.td = oe_sgx_get_td();

    // Expect the state to be RUNNING upon entering
    OE_EXPECT(_thread_info.td->state, OE_TD_STATE_RUNNING);

    // Expect the flag is not set
    OE_TEST(!oe_sgx_td_is_handling_host_signal(_thread_info.td));

    host_get_tid(&self_tid);

    // Expect the state to be RUNNING after an ocall
    OE_EXPECT(_thread_info.td->state, OE_TD_STATE_RUNNING);

    OE_TEST(tid == self_tid);
    _thread_info.tid = tid;

    printf("(tid=%d) thread is running...\n", _thread_info.tid);

    OE_CHECK(oe_add_vectored_exception_handler(false, td_state_handler));

    // Invoke the internal API to unmask host signals
    oe_sgx_td_unmask_host_signal(_thread_info.td);

    // Ensure the order of setting the lock
    asm volatile("" ::: "memory");

    __atomic_store_n(_host_lock_state, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(_host_lock_state, __ATOMIC_ACQUIRE) != 2)
    {
        asm volatile("pause" ::: "memory");
    }

    // Expect the state to be persisted after an interrupt
    OE_EXPECT(_thread_info.td->state, OE_TD_STATE_RUNNING);

    // Expect the flag is cleared
    OE_TEST(!oe_sgx_td_is_handling_host_signal(_thread_info.td));

    // Expect td->host_signal is cleared
    OE_TEST(_thread_info.td->host_signal == 0);

    // Expect the signal is unregistered by the handler
    OE_TEST(!oe_sgx_td_host_signal_registered(_thread_info.td, SIGUSR1));

    printf("(tid=%d) interrupt is handled...\n", self_tid);

    __atomic_store_n(_host_lock_state, 3, __ATOMIC_RELEASE);

    // Make a ocall to spin and wait for an interrupt on the host
    host_spin();

    while (__atomic_load_n(_host_lock_state, __ATOMIC_ACQUIRE) != 5)
    {
        asm volatile("pause" ::: "memory");
    }

    // Expect the state to be RUNNING after an OCALL
    OE_EXPECT(_thread_info.td->state, OE_TD_STATE_RUNNING);

    {
        uint32_t a, b, c, d;
        cpuid(1, 0, &a, &b, &c, &d);
    }

    // Expect the state to be persisted after an illegal instruction
    // emulation
    OE_EXPECT(_thread_info.td->state, OE_TD_STATE_RUNNING);

    divide_by_zero_exception_function();

    // Expect the state to be persisted after an exception.
    OE_EXPECT(_thread_info.td->state, OE_TD_STATE_RUNNING);

    OE_CHECK(oe_remove_vectored_exception_handler(td_state_handler));

    printf("(tid=%d) thread is exiting...\n", self_tid);
done:
    return;
}

void enc_td_state(uint64_t lock_state)
{
    oe_result_t result;
    int tid = 0;

    {
        uint32_t a, b, c, d;
        cpuid(1, 0, &a, &b, &c, &d);
    }

    host_get_tid(&tid);
    OE_TEST(tid != 0);

    /* Set up the lock_state points to the host*/
    _host_lock_state = (int*)lock_state;

    printf("(tid=%d) Create a thread...\n", tid);

    result = host_create_thread();
    if (result != OE_OK)
        return;

    while (__atomic_load_n(_host_lock_state, __ATOMIC_ACQUIRE) != 1)
    {
        asm volatile("pause" ::: "memory");
    }

    OE_TEST(_thread_info.tid != 0);
    host_sleep_msec(30);

    OE_TEST(oe_sgx_td_register_host_signal(_thread_info.td, SIGUSR1) == true);

    printf(
        "(tid=%d) Sending interrupt to (td=0x%lx, tid=%d) inside the "
        "enclave...\n",
        tid,
        (uint64_t)_thread_info.td,
        _thread_info.tid);

    host_send_interrupt(_thread_info.tid, SIGUSR1);

    while (__atomic_load_n(_host_lock_state, __ATOMIC_ACQUIRE) != 4)
    {
        asm volatile("pause" ::: "memory");
    }

    // Expect the target td's state to be EXITED while
    // running in the host context
    OE_EXPECT(_thread_info.td->state, OE_TD_STATE_EXITED);

    host_sleep_msec(30);

    printf(
        "(tid=%d) Sending interrupt to (td=0x%lx, tid=%d) on the "
        "host...\n",
        tid,
        (uint64_t)_thread_info.td,
        _thread_info.tid);

    // Expect the host execution to be interrupted by SIGUSR1
    host_send_interrupt(_thread_info.tid, SIGUSR1);

    host_join_thread();

    // Expect the target td's state to be EXITED
    OE_EXPECT(_thread_info.td->state, OE_TD_STATE_EXITED);
}

static uint64_t td_state_handler_no_return(
    oe_exception_record_t* exception_record)
{
    if (exception_record->code == OE_EXCEPTION_DIVIDE_BY_ZERO)
    {
        oe_longjmp(&jump_buffer, 1);
    }

    return OE_EXCEPTION_ABORT_EXECUTION;
}

void enc_run_thread_handler_no_return(int tid)
{
    oe_result_t result = OE_OK;

    _thread_handler_no_return_info.tid = tid;
    _thread_handler_no_return_info.td = oe_sgx_get_td();

    printf(
        "(tid=%d) thread is created td=0x%lx\n",
        _thread_handler_no_return_info.tid,
        (uint64_t)_thread_handler_no_return_info.td);

    OE_CHECK(
        oe_add_vectored_exception_handler(false, td_state_handler_no_return));

    if (oe_setjmp(&jump_buffer) == 0)
        divide_by_zero_exception_function();

    // Expect the state is still OE_TD_STATE_SECOND_LEVEL_EXCEPTION_HANDLING
    // (the handler does not return)
    OE_EXPECT(
        _thread_handler_no_return_info.td->state,
        OE_TD_STATE_SECOND_LEVEL_EXCEPTION_HANDLING);

done:
    return;
}

void enc_run_thread_reuse_tcs(int tid)
{
    oe_sgx_td_t* td = oe_sgx_get_td();

    // Expect the tcs is re-used
    OE_EXPECT(td, _thread_handler_no_return_info.td);

    OE_EXPECT(_thread_handler_no_return_info.td->state, OE_TD_STATE_RUNNING);

    printf("(tid=%d) thread is created td=0x%lx\n", tid, (uint64_t)td);
}

void enc_td_state_handler_no_return()
{
    oe_result_t result;
    int tid = 0;

    host_get_tid(&tid);
    OE_TEST(tid != 0);

    printf("(tid=%d) Create a thread...\n", tid);

    result = host_create_thread_handler_no_return();
    if (result != OE_OK)
        return;

    host_join_thread();

    printf("(tid=%d) Create a thread...\n", tid);

    result = host_create_thread_reuse_tcs();
    if (result != OE_OK)
        return;

    host_join_thread();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
