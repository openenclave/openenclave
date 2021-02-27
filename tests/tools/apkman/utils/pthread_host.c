// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <pthread.h>
#include <unistd.h>

#include "pthread_u.h"

typedef struct thread_arg
{
    oe_enclave_t* enc;
    uint64_t thread_started;
} thread_arg_t;

static void* _launch_enclave_thread(void* a)
{
    thread_arg_t* arg = (thread_arg_t*)a;
    oe_enclave_thread_launch_ecall(
        arg->enc, (uint64_t)pthread_self(), &arg->thread_started);
    return NULL;
}

void oe_host_thread_create_ocall(oe_enclave_t* enc)
{
    thread_arg_t arg = {enc, 0};
    pthread_t id = 0;
    pthread_create(&id, NULL, _launch_enclave_thread, &arg);
    while (((volatile thread_arg_t*)&arg)->thread_started == 0)
        usleep(1);
}

int oe_host_thread_join_ocall(uint64_t host_thread_id)
{
    return pthread_join((pthread_t)(void*)host_thread_id, NULL);
}

int oe_host_thread_detach_ocall(uint64_t host_thread_id)
{
    return pthread_detach((pthread_t)(void*)host_thread_id);
}
