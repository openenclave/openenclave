// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "thread_interrupt_u.h"

#define SKIP_RETURN_CODE 2

oe_enclave_t* enclave;
static pthread_t _thread;

void host_send_interrupt(int tid, int signal_number)
{
    pid_t pid = getpid();
    syscall(SYS_tgkill, pid, tid, signal_number);
}

int host_get_tid()
{
    return (pid_t)syscall(SYS_gettid);
}

static void* _thread_function(void* arg)
{
    uint64_t blocking = (uint64_t)arg;
    pid_t tid = (pid_t)syscall(SYS_gettid);

    if (blocking)
        enc_run_thread_blocking(enclave, tid);
    else
        enc_run_thread_nonblocking(enclave, tid);

    return NULL;
}

void host_create_thread(uint64_t blocking)
{
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_create(&_thread, &attr, _thread_function, (void*)blocking);
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

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH testname\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf("=== Skipped unsupported test in simulation mode "
               "(thread_interrupt)\n");
        return SKIP_RETURN_CODE;
    }

    if ((result = oe_create_thread_interrupt_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    if (!strcmp(argv[2], "nonblocking"))
    {
        result = enc_thread_interrupt_nonblocking(enclave);
        if (result != OE_OK)
            oe_put_err("oe_call_enclave() failed: result=%u", result);
        OE_TEST(oe_terminate_enclave(enclave) == OE_OK);
    }
    else if (!strcmp(argv[2], "blocking"))
    {
        result = enc_thread_interrupt_blocking(enclave);
        OE_TEST(result == OE_ENCLAVE_ABORTING);
        /* Expcet a non-OE_OK result. The error code may be different
         * between debug and release build. */
        OE_TEST(oe_terminate_enclave(enclave) != OE_OK);
    }
    else
    {
        fprintf(stderr, "Unknown test case");
        return 1;
    }

    printf("=== passed all tests (thread_interrupt)\n");

    return 0;
}
