// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "td_state_u.h"

#define SKIP_RETURN_CODE 2

oe_enclave_t* enclave;
static pthread_t _thread;
volatile static int _lock_state;

int host_get_tid()
{
    return (pid_t)syscall(SYS_gettid);
}

void host_spin()
{
    int return_value;
    int tid = host_get_tid();

    printf("(tid=%d) thread is spinning on the host...\n", tid);

    _lock_state = 4;
    return_value = poll(NULL, 0, -1);
    // Expect to be interrupted and return -1
    OE_TEST(return_value == -1);
    printf("(tid=%d) thread is interrupted on the host...\n", tid);
    _lock_state = 5;
}

void host_send_interrupt(int tid, int signal_number)
{
    pid_t pid = getpid();
    syscall(SYS_tgkill, pid, tid, signal_number);
}

static void* _thread_function()
{
    pid_t tid = (pid_t)syscall(SYS_gettid);

    enc_run_thread(enclave, tid);

    return NULL;
}

void host_create_thread()
{
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_create(&_thread, &attr, _thread_function, NULL);
    pthread_attr_destroy(&attr);
}

static void* _thread_function_handler_no_return()
{
    pid_t tid = (pid_t)syscall(SYS_gettid);

    enc_run_thread_handler_no_return(enclave, tid);

    return NULL;
}

void host_create_thread_handler_no_return()
{
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_create(&_thread, &attr, _thread_function_handler_no_return, NULL);
    pthread_attr_destroy(&attr);
}

static void* _thread_function_reuse_tcs()
{
    pid_t tid = (pid_t)syscall(SYS_gettid);

    enc_run_thread_reuse_tcs(enclave, tid);

    return NULL;
}

void host_create_thread_reuse_tcs()
{
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_create(&_thread, &attr, _thread_function_reuse_tcs, NULL);
    pthread_attr_destroy(&attr);
}

void host_join_thread()
{
    pthread_join(_thread, NULL);
}

void host_sleep_msec(uint32_t msec)
{
    struct timespec ts;

    ts.tv_sec = (uint64_t)msec / 1000;
    ts.tv_nsec = ((int64_t)msec % 1000) * 1000000;

    nanosleep(&ts, NULL);
}

int main(int argc, const char* argv[])
{
    oe_result_t result;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH testname\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf("=== Skipped unsupported test in simulation mode "
               "(td_state)\n");
        return SKIP_RETURN_CODE;
    }

    if ((result = oe_create_td_state_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    printf("=== test the td state on a thread\n");

    result = enc_td_state(enclave, (uint64_t)&_lock_state);
    if (result != OE_OK)
        oe_put_err("oe_call_enclave() failed: result=%u", result);

    printf("=== test the handler no return\n");

    result = enc_td_state_handler_no_return(enclave);
    if (result != OE_OK)
        oe_put_err("oe_call_enclave() failed: result=%u", result);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (td_state)\n");

    return 0;
}
