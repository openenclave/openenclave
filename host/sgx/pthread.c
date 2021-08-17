// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/raise.h>
#include "../hostthread.h"
#include "platform_u.h"
#include "syscall_u.h"

#define CREATE_ENCLAVE_THREAD_NUM_TRIES (10)

typedef struct _thread_arg
{
    oe_enclave_t* enc;
    uint64_t thread_started;
    int launch_failed;
} oe_thread_arg_t;

static void* _launch_enclave_thread(void* a)
{
    oe_thread_arg_t* arg = (oe_thread_arg_t*)a;

    for (int i = 0; i < CREATE_ENCLAVE_THREAD_NUM_TRIES; ++i)
    {
        oe_result_t result = oe_enclave_thread_launch_ecall(
            arg->enc, (uint64_t)oe_thread_self(), &arg->thread_started);
        if (result == OE_OK)
            return NULL;

        OE_TRACE_VERBOSE(
            "oe_enclave_thread_launch_ecall failed with error %s\n.",
            oe_result_str(result));
    }

    arg->launch_failed = 1;
    return NULL;
}

int oe_host_thread_create_ocall(oe_enclave_t* enc, bool detached)
{
    oe_thread_arg_t arg = {enc, 0, 0};
    oe_thread_t id = 0;

    // Create host thread that will go on to launch an enclave thread.
    int r = oe_thread_create(&id, _launch_enclave_thread, &arg);
    if (r != 0)
        return -1;

    // Wait until the enclave thread has started or the launch has failed.
    while (!arg.thread_started && !arg.launch_failed)
    {
        // Sleep for 1 millisecond.
        oe_timespec tspec = {0, 0};
        tspec.tv_nsec = 1000;
        oe_syscall_nanosleep_ocall(&tspec, NULL);
    }

    if (arg.thread_started)
    {
        if (detached)
            oe_thread_detach(id);
    }

    return arg.launch_failed ? -1 : 0;
}

int oe_host_thread_join_ocall(uint64_t host_thread_id)
{
    return oe_thread_join((oe_thread_t)host_thread_id);
}

int oe_host_thread_detach_ocall(uint64_t host_thread_id)
{
    return oe_thread_detach((oe_thread_t)host_thread_id);
}
