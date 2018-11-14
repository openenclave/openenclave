// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
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
#include <map>
#include <thread>
#include <vector>
#include "../host/args.h"
#include "../host/ocalls.h"
#include "../host/threadArgs.h"

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

static std::vector<std::function<void*()>> _thread_functions;
static int _next_enc_thread_id = 0;
int enc_key = 0; // Monotonically increasing enclave key
static std::map<int, pthread_t> _key_to_thread_id_map; // Map of enc_key to
                                                       // thread_id returned by
                                                       // pthread_self()

static std::atomic_flag _enc_lock = ATOMIC_FLAG_INIT;
// Each new thread will point to memory created by the host after thread
// creation
ThreadArgs* thread_args[MAX_ENC_KEYS];

static int _pthread_create_hook(
    pthread_t* enc_thread,
    const pthread_attr_t* attr,
    void* (*start_routine)(void*),
    void* arg)
{
    *enc_thread = 0;
    _acquire_lock(&_enc_lock);
    _thread_functions.push_back(
        [start_routine, arg]() { return start_routine(arg); });
    enc_key = ++_next_enc_thread_id;
    printf("pthread_create_hook(): enc_key is %d\n", enc_key);
    // Populate the enclave key to thread id map in advance
    _key_to_thread_id_map.emplace(enc_key, *enc_thread);
    _release_lock(&_enc_lock);

    if (_next_enc_thread_id > (int)(MAX_ENC_KEYS - 1))
    {
        printf(
            "Exceeded max number of enclave threads supported %d\n",
            (int)MAX_ENC_KEYS - 1);
    }

    // Send the enclave id so that host can maintain the map between
    // enclave and host id
    if (oe_call_host("host_create_pthread", (void*)(uint64_t)enc_key) != OE_OK)
    {
        printf(
            "pthread_create_hook(): Error in call to host host_create_pthread "
            "for enc_key=%d\n",
            enc_key);
        oe_abort();
    }

    // Block until the enclave pthread_id becomes available in the map
    while (*enc_thread == 0)
    {
        _acquire_lock(&_enc_lock);
        *enc_thread = _key_to_thread_id_map[enc_key];
        _release_lock(&_enc_lock);
        if (*enc_thread == 0)
        {
            std::this_thread::sleep_for(std::chrono::microseconds(20 * 1000));
        }
    }

    printf(
        "_pthread_create_hook(): pthread_create success for enc_key=%d; thread "
        "id=0x%lu\n",
        enc_key,
        *enc_thread);
    return 0;
}

static int _pthread_join_hook(pthread_t enc_thread, void** value_ptr)
{
    // Find the enc_key from the enc_thread
    _acquire_lock(&_enc_lock);
    auto it = std::find_if(
        _key_to_thread_id_map.begin(),
        _key_to_thread_id_map.end(),
        [&enc_thread](const std::pair<int, pthread_t> p) {
            return p.second == enc_thread;
        });
    if (it == _key_to_thread_id_map.end())
    {
        printf(
            "_pthread_join_hook(): Error: enc_key for thread ID 0x%lu not "
            "found\n",
            enc_thread);
        oe_abort();
    }
    int join_enc_key = it->first;
    ThreadArgs* thrd_join_args = thread_args[join_enc_key - 1];
    if (thrd_join_args == NULL)
    {
        _release_lock(&_enc_lock);
        return EINVAL;
    }
    thrd_join_args->enc_key = (uint64_t)join_enc_key;
    thrd_join_args->join_value_ptr = value_ptr;
    _release_lock(&_enc_lock);

    printf(
        "_pthread_join_hook(): enc_key for thread ID 0x%lu is %d\n",
        enc_thread,
        join_enc_key);
    if (oe_call_host("host_join_pthread", (void*)thrd_join_args) != OE_OK)
    {
        printf(
            "pthread_join_hook(): Error in call to host host_join_pthread for "
            "enc_key=%d\n",
            join_enc_key);
        oe_abort();
    }

    int join_ret;
    _acquire_lock(&_enc_lock);
    join_ret = thrd_join_args->join_ret;

    // Since join succeeded, delete the _key_to_thread_id_map
    if (!join_ret)
    {
        _key_to_thread_id_map.erase(join_enc_key);
    }
    _release_lock(&_enc_lock);

    return join_ret;
}

static int _pthread_detach_hook(pthread_t enc_thread)
{
    // Find the enc_key from the enc_thread
    _acquire_lock(&_enc_lock);
    auto it = std::find_if(
        _key_to_thread_id_map.begin(),
        _key_to_thread_id_map.end(),
        [&enc_thread](const std::pair<int, pthread_t> p) {
            return p.second == enc_thread;
        });
    if (it == _key_to_thread_id_map.end())
    {
        _release_lock(&_enc_lock);
        printf(
            "_pthread_detach_hook(): Error enc_key for thread ID 0x%lu not "
            "found\n",
            enc_thread);
        oe_abort();
    }
    int det_enc_key = it->first;
    ThreadArgs* thrd_det_args = thread_args[det_enc_key - 1];
    if (thrd_det_args == NULL)
    {
        _release_lock(&_enc_lock);
        return EINVAL;
    }

    thrd_det_args->enc_key = (uint64_t)det_enc_key;
    _release_lock(&_enc_lock);

    printf(
        "_pthread_detach_hook(): Enclave Key for thread ID 0x%lu is %d\n",
        enc_thread,
        det_enc_key);
    if (oe_call_host("host_detach_pthread", (void*)thrd_det_args) != OE_OK)
    {
        printf(
            "_pthread_detach_hook(): Error in call to host host_detach_pthread "
            "for enc_key=%d\n",
            det_enc_key);
        oe_abort();
    }

    // Since detach succeeded, delete the _key_to_thread_id_map
    _acquire_lock(&_enc_lock);
    int det_ret = thrd_det_args->detach_ret;
    if (!det_ret)
    {
        if (thrd_det_args->enc_key > OE_INT_MAX)
            oe_abort();
        _key_to_thread_id_map.erase((int)thrd_det_args->enc_key);
    }
    _release_lock(&_enc_lock);

    return det_ret;
}

// Launches the new thread in the enclave
OE_ECALL void _enclave_launch_thread(void* args_)
{
    thread_args[enc_key - 1] = (ThreadArgs*)
        args_; // Set the global value to that obtained from the host

    if (thread_args[enc_key - 1] == NULL)
    {
        printf("_enclave_launch_thread(): Invalid thread_args from host\n");
        oe_abort();
    }

    std::function<void()> f;

    _acquire_lock(&_enc_lock);
    _key_to_thread_id_map[(int)((thread_args[enc_key - 1])->enc_key)] =
        pthread_self();
    _release_lock(&_enc_lock); // Release the lock so that pthread_create can
                               // acquire the lock

    _acquire_lock(&_enc_lock);
    f = _thread_functions.back();
    _thread_functions.pop_back();
    _release_lock(&_enc_lock);
    f();
}

OE_ECALL void Test(Args* args)
{
    static oe_pthread_hooks_t _hooks = {.create = _pthread_create_hook,
                                        .join = _pthread_join_hook,
                                        .detach = _pthread_detach_hook};
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
    1,     /* ProductID */
    1,     /* SecurityVersion */
    true,  /* AllowDebug */
    12288, /* HeapPageCount */
    1024,  /* StackPageCount */
    8);    /* TCSCount */

OE_DEFINE_EMPTY_ECALL_TABLE();
