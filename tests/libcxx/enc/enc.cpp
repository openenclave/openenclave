// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/pthreadhooks.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <thread>
#include <vector>
#include "../host/threadArgs.h"
#include "libcxx_t.h"

extern const char* __test__;

extern "C" int main(int argc, const char* argv[]);

extern "C" void _exit(int status)
{
    host_exit(status);
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

Handler signal(int, Handler)
{
    /* Ignore! */
    return NULL;
}

extern "C" int close(int fd)
{
    OE_UNUSED(fd);
    OE_TEST("close() panic" == NULL);
    return 0;
}

static std::vector<std::function<void*()>> _thread_functions;
static uint64_t _next_enc_thread_id = 0;
static uint64_t _enc_key = 0; // Monotonically increasing enclave key

// Map of enc_key to thread_id returned by pthread_self()
static std::map<uint64_t, std::atomic<pthread_t>> _key_to_thread_id_map;

static atomic_flag_lock _enc_lock;

struct thread_args
{
    uint64_t enc_key;
    int join_ret;
    int detach_ret;
};
// Each new thread will point to memory created by the host after thread
// creation
thread_args _thread_args[MAX_ENC_KEYS];

static int _pthread_create_hook(
    pthread_t* enc_thread,
    const pthread_attr_t*,
    void* (*start_routine)(void*),
    void* arg)
{
    *enc_thread = 0;
    uint64_t enc_key;
    const std::atomic<pthread_t>* enc_value;
    {
        atomic_lock lock(_enc_lock);
        _thread_functions.push_back(
            [start_routine, arg]() { return start_routine(arg); });
        enc_key = _enc_key = ++_next_enc_thread_id;
        printf("_pthread_create_hook(): enc_key is %lu\n", enc_key);
        // Populate the enclave key to thread id map in advance
        enc_value = &_key_to_thread_id_map[enc_key];

        if (_next_enc_thread_id > (MAX_ENC_KEYS - 1))
        {
            printf(
                "Exceeded max number of enclave threads supported %lu\n",
                MAX_ENC_KEYS - 1);
        }
    }

    // Send the enclave id so that host can maintain the map between
    // enclave and host id
    if (OE_OK != host_create_thread(enc_key, oe_get_enclave()))
    {
        printf(
            "_pthread_create_hook(): Error in call to host_create_pthread "
            "for enc_key=%lu\n",
            enc_key);
        oe_abort();
    }

    // Block until the enclave pthread_id becomes available in the map
    while (*enc_value == 0)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    *enc_thread = *enc_value;

    printf(
        "_pthread_create_hook(): pthread_create success for enc_key=%lu; "
        "thread id=%#10lx\n",
        _enc_key,
        *enc_thread);

    return 0;
}

static int _pthread_join_hook(pthread_t enc_thread, void**)
{
    // Find the enc_key from the enc_thread
    uint64_t join_enc_key;
    {
        atomic_lock lock(_enc_lock);
        const auto it = std::find_if(
            _key_to_thread_id_map.begin(),
            _key_to_thread_id_map.end(),
            [&enc_thread](const std::pair<uint64_t, pthread_t>& p) {
                return p.second == enc_thread;
            });
        if (it == _key_to_thread_id_map.end())
        {
            printf(
                "_pthread_join_hook(): Error: enc_key for thread ID %#10lx not "
                "found\n",
                enc_thread);
            oe_abort();
        }

        join_enc_key = it->first;
        _thread_args[join_enc_key - 1].enc_key = join_enc_key;
    }

    printf(
        "_pthread_join_hook(): enc_key for thread ID %#10lx is %ld\n",
        enc_thread,
        join_enc_key);

    int join_ret = 0;
    if (host_join_thread(&join_ret, join_enc_key) != OE_OK)
    {
        printf(
            "_pthread_join_hook(): Error in call to host host_join_pthread for "
            "enc_key=%ld\n",
            join_enc_key);
        oe_abort();
    }

    {
        atomic_lock lock(_enc_lock);
        _thread_args[join_enc_key - 1].join_ret = join_ret;

        // Since join succeeded, delete the _key_to_thread_id_map
        if (!join_ret)
        {
            _key_to_thread_id_map.erase(join_enc_key);
        }
    }

    return join_ret;
}

static int _pthread_detach_hook(pthread_t enc_thread)
{
    // Find the enc_key from the enc_thread
    uint64_t det_enc_key;
    {
        atomic_lock lock(_enc_lock);
        const auto it = std::find_if(
            _key_to_thread_id_map.begin(),
            _key_to_thread_id_map.end(),
            [&enc_thread](const std::pair<uint64_t, pthread_t>& p) {
                return p.second == enc_thread;
            });
        if (it == _key_to_thread_id_map.end())
        {
            printf(
                "_pthread_detach_hook(): Error: enc_key for thread ID %#10lx "
                "not found\n",
                enc_thread);
            oe_abort();
        }

        det_enc_key = it->first;
        _thread_args[det_enc_key - 1].enc_key = det_enc_key;
    }

    printf(
        "_pthread_detach_hook(): enc_key for thread ID %#10lx is %ld\n",
        enc_thread,
        det_enc_key);

    int det_ret = 0;
    if (host_detach_thread(&det_ret, det_enc_key) != OE_OK)
    {
        printf(
            "_pthread_detach_hook(): Error in call to host host_detach_thread "
            "for enc_key=%ld\n",
            det_enc_key);
        oe_abort();
    }

    // Since detach succeeded, delete the _key_to_thread_id_map
    if (0 == det_ret)
    {
        atomic_lock lock(_enc_lock);
        _key_to_thread_id_map.erase(det_enc_key);
    }

    return det_ret;
}

// Launches the new thread in the enclave
void enc_enclave_thread(uint64_t enc_key)
{
    _thread_args[_enc_key - 1].enc_key = enc_key;
    _thread_args[_enc_key - 1].join_ret = -1;
    _thread_args[_enc_key - 1].detach_ret = -1;

    std::function<void()> f;

    {
        atomic_lock lock(_enc_lock);
        _key_to_thread_id_map[enc_key] = pthread_self();
    }

    std::this_thread::yield();

    {
        atomic_lock lock(_enc_lock);
        f = _thread_functions.back();
        _thread_functions.pop_back();
    }
    f();
}

int enc_test(char test_name[STRLEN])
{
    static oe_pthread_hooks_t _hooks = {.create = _pthread_create_hook,
                                        .join = _pthread_join_hook,
                                        .detach = _pthread_detach_hook};
    static const char* argv[] = {
        "test",
        NULL,
    };
    static const int argc = sizeof(argv) / sizeof(argv[0]);

    extern const char* __TEST__NAME;

    oe_register_pthread_hooks(&_hooks);

    strncpy(test_name, __TEST__NAME, STRLEN);
    test_name[STRLEN - 1] = '\0';

    printf("RUNNING: %s\n", __TEST__NAME);
    return main(argc, argv);
}

OE_SET_ENCLAVE_SGX(
    1,                   /* ProductID */
    1,                   /* SecurityVersion */
    true,                /* Debug */
#ifdef FULL_LIBCXX_TESTS /* Full tests require large heap memory. */
    12288,               /* NumHeapPages */
#else
    512, /* NumHeapPages */
#endif
    512, /* NumStackPages */
    8);  /* NumTCS */
