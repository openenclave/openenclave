// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <inttypes.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <unordered_map>
#include "openssl_u.h"

#include "threadArgs.h"

// Host maintains a map of enclave key to host thread ID
static std::unordered_map<uint64_t, std::atomic<std::thread::id>>
    _enclave_host_id_map;
// Host maintains a map of thread id to the thread object
static std::unordered_map<std::thread::id, std::thread> _host_id_thread_map;

static atomic_flag_lock _host_lock;

void host_exit(int arg)
{
    // Ensure all the threads terminate before the exit
    for (auto& pair : _host_id_thread_map)
    {
        pair.second.join();
    }
    exit(arg);
}

struct thread_args_t
{
    oe_enclave_t* enclave;
    uint64_t enc_key;
};

void* host_enclave_thread(void* args)
{
    thread_args_t* thread_args = reinterpret_cast<thread_args_t*>(args);
    // need to cache the values for enc_key and enclave now before _host_lock
    // is unlocked after assigning the thread_id to the _enclave_host_id_map
    // because args is a local variable in the calling method which may exit
    // at any time after _host_lock is unlocked which may cause a segfault
    uint64_t enc_key = thread_args->enc_key;
    oe_enclave_t* enclave = thread_args->enclave;
    std::thread::id thread_id;

    {
        // Using atomic_thread_host_id_map lock to ensure the mapping is updated
        // before the thread_id lookup
        atomic_lock lock(_host_lock);

        std::thread::id thread_id = std::this_thread::get_id();
        OE_TEST(
            _host_id_thread_map.find(thread_id) != _host_id_thread_map.end());

        // Populate the enclave_host_id map with the thread_id
        _enclave_host_id_map[enc_key] = thread_id;
    }

    // Launch the thread
    oe_result_t result = enc_enclave_thread(enclave, enc_key);
    OE_TEST(result == OE_OK);

    return NULL;
}

void host_create_thread(uint64_t enc_key, oe_enclave_t* enclave)
{
    thread_args_t thread_args = {enclave, enc_key};
    std::thread::id thread_id;
    const std::atomic<std::thread::id>* mapped_thread_id;

    {
        // Using atomic locks to protect the enclave_host_id_map
        // and update the _host_id_thread_map upon the thread creation
        atomic_lock lock(_host_lock);
        mapped_thread_id = &_enclave_host_id_map[enc_key];

        // New Thread is created and executes host_enclave_thread
        std::thread t = std::thread(host_enclave_thread, &thread_args);

        thread_id = t.get_id();
        _host_id_thread_map[thread_id] = std::move(t);
    }

    // Main host thread waits for the enclave id to host id mapping to be
    // updated
    while (*mapped_thread_id == std::thread::id())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // Sanity check
    if (thread_id != *mapped_thread_id)
    {
        printf("Host thread id incorrect in the enclave_host_id_map\n");
        abort();
    }
}

int host_join_thread(uint64_t enc_key)
{
    int ret_val = 0;
    std::thread::id thread_id;

    // Find the thread_id from the enclave_host_id_map using the enc_key
    {
        // Using atomic locks to protect the enclave_host_id_map
        atomic_lock lock(_host_lock);
        const auto it = _enclave_host_id_map.find(enc_key);
        if (it != _enclave_host_id_map.end())
        {
            thread_id = it->second;
            lock.unlock();

            auto& t = _host_id_thread_map[thread_id];
            OE_TEST(t.joinable());
            t.join();

            // Update the shared memory only after join
            {
                // Delete the enclave_host_id mapping as the thread_id may be
                // reused in future
                lock.lock();
                _enclave_host_id_map.erase(enc_key);
            }
        }
        else
        {
            printf(
                "host_join_thread() failed to find enclave id=%" PRIu64
                " in host "
                "map\n",
                enc_key);
            abort();
        }
    }

    return ret_val;
}

int host_detach_thread(uint64_t enc_key)
{
    // Find the thread_id from the enclave_host_id_map using the enc_key

    // Using atomic locks to protect the enclave_host_id_map
    atomic_lock lock(_host_lock);
    const auto it = _enclave_host_id_map.find(enc_key);
    if (it != _enclave_host_id_map.end())
    {
        std::thread::id thread_id = it->second;
        lock.unlock();

        auto& t = _host_id_thread_map[thread_id];
        t.detach();

        {
            // Delete the _enclave_host_id mapping as the host thread_id may be
            // reused in future
            lock.lock();
            _enclave_host_id_map.erase(enc_key);
        }
    }
    else
    {
        printf(
            "host_detach_thread() failed to find enclave key=%" PRIu64
            " in host "
            "map\n",
            enc_key);
        abort();
    }
    return 0;
}

#ifdef __linux__
extern char** environ;
char** _environ = environ; // _environ is defined by stdlib.h on Windows.
#endif

void test(oe_enclave_t* enclave, int argc, char** argv)
{
    int ret = 1;
    char** env = _environ;

    oe_result_t result = enc_test(enclave, &ret, argc, argv, env);
    OE_TEST(result == OE_OK);

    if (ret == 0)
    {
        printf("PASSED: %s\n", argv[0]);
    }
    else
    {
        printf("FAILED: %s (ret=%d)\n", argv[0], ret);
        abort();
    }
}

static int _get_opt(
    int& argc,
    char* argv[],
    const char* name,
    const char** arg = NULL)
{
    for (int i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], name) == 0)
        {
            if (!arg)
            {
                memmove(
                    (void*)&argv[i],
                    &argv[i + 1],
                    static_cast<size_t>(argc - i) * sizeof(char*));
                argc--;
                return 1;
            }

            if (i + 1 == argc)
            {
                return -1;
            }

            *arg = argv[i + 1];
            memmove(
                (char**)&argv[i],
                &argv[i + 2],
                static_cast<size_t>(argc - i - 1) * sizeof(char*));
            argc -= 2;
            return 1;
        }
    }

    return 0;
}

int main(int argc, char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;

    /* Check for the --sim option. */
    if (_get_opt(argc, argv, "--simulate") == 1)
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }
    else
    {
        flags = oe_get_create_flags();
    }

    /* Check the argument count. */
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE testname\n", argv[0]);
        exit(1);
    }

    printf("=== %s: %s %s\n", argv[0], argv[1], argv[2]);

    /* Create the enclave. */
    if ((result = oe_create_openssl_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
    }

    /*
     * Ignore the first two arguments (i.e., host and enclave) and
     * invoke enc_test().
     */
    test(enclave, argc - 2, (char**)(&argv[2]));

    /* Shutdown the enclave. */
    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("\n");

    return 0;
}
