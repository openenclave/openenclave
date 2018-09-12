// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/pthreadhooks.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <vector>
#include "../host/args.h"
#include "../host/ocalls.h"

extern const char* __test__;

extern "C" int main(int argc, const char* argv[]);

extern "C" void _exit(int status)
{
    oe_call_host("ocall_exit", (void*)(long)status);
    abort();
}

extern "C" void _Exit(int status)
{
    _exit(status);
    abort();
}

extern "C" void exit(int status)
{
    _exit(status);
    abort();
}

typedef void (*Handler)(int signal);

Handler signal(int signal, Handler)
{
    /* Ignore! */
    return NULL;
}

extern "C" int close(int fd)
{
    OE_TEST("close() panic" == NULL);
    return 0;
}

static std::vector<std::function<void()>> _thread_functions;
static std::atomic_flag _lock = ATOMIC_FLAG_INIT;
static pthread_t _next_thread_id = 0;

static void _acquire_lock()
{
    while (_lock.test_and_set(std::memory_order_acquire))
        ;
}

static void _release_lock()
{
    _lock.clear(std::memory_order_release);
}

/* pthread function prototypes
int pthread_create(pthread_t *__restrict, const pthread_attr_t *__restrict, void
*(*)(void *), void *__restrict);
int pthread_detach(pthread_t);
_Noreturn void pthread_exit(void *);
int pthread_join(pthread_t, void **);
*/
static int _pthread_create_hook(
    pthread_t* thread,
    const pthread_attr_t* attr,
    void* (*start_routine)(void*),
    void* arg)
{
    // enc_stack(enc_func_ptr);
    // Call host to create thread
    // my_pthread_create_ocall(thread, attr, enc_func_ptr, arg);

    _acquire_lock();

    _thread_functions.push_back([start_routine, arg]() { start_routine(arg); });

    *thread = ++_next_thread_id;
    _release_lock();

    if (oe_call_host("host_create_pthread", NULL) != OE_OK)
        oe_abort();

    return 0;
}

OE_ECALL void _EnclaveLaunchThread()
{
    std::function<void()> f;
    _acquire_lock();
    f = _thread_functions.back();
    _thread_functions.pop_back();
    _release_lock();
    f();
}

OE_ECALL void Test(Args* args)
{
    static oe_pthread_hooks_t _hooks = {.create = _pthread_create_hook};
    oe_register_pthread_hooks(&_hooks);

    extern const char* __TEST__NAME;
    if (args)
    {
        printf("RUNNING: %s\n", __TEST__NAME);
        static const char* argv[] = {
            "test", NULL,
        };
        static int argc = sizeof(argv) / sizeof(argv[0]);
        args->ret = main(argc, argv);
        args->test = oe_host_strndup(__TEST__NAME, OE_SIZE_MAX);
    }
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    8192, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
