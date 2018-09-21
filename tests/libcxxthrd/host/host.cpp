// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <thread>
#include "args.h"
#include "ocalls.h"
#include "threadArgs.h"

// Host maintains a map of enclave key to host thread ID
static std::map<uint64_t, pthread_t> enclave_host_id_map;
static std::atomic_flag _host_lock = ATOMIC_FLAG_INIT;

void Test(oe_enclave_t* enclave)
{
    Args args;
    args.ret = 1;
    args.test = NULL;
    oe_result_t result = oe_call_enclave(enclave, "Test", &args);
    OE_TEST(result == OE_OK);

    if (args.ret == 0)
    {
        printf("PASSED: %s\n", args.test);
    }
    else
    {
        printf("FAILED: %s (ret=%d)\n", args.test, args.ret);
        abort();
    }
}

OE_OCALL void ocall_exit(uint64_t arg)
{
    exit(arg);
}

void* EnclaveThread(void* args)
{
    ThreadArgs* thread_args = (ThreadArgs*)args;
    pthread_t host_thread_id = pthread_self();

    printf("EnclaveThread() -- enc_key is %lu\n", thread_args->enc_key);
    _acquire_lock(&_host_lock);
    // Populate the enclave_host_id map with the host thread id
    enclave_host_id_map[thread_args->enc_key] = host_thread_id;
    printf(
        "EnclaveThread(): Enc key=%lu has Host id of 0x%lu\n",
        thread_args->enc_key,
        host_thread_id);
    _release_lock(&_host_lock);

    // Launch the thread
    oe_result_t result =
        oe_call_enclave(thread_args->enclave, "_enclave_launch_thread", NULL);
    OE_TEST(result == OE_OK);

    return NULL;
}

OE_OCALL void host_create_pthread(uint64_t enc_key, oe_enclave_t* enclave)
{
    ThreadArgs* thread_args = new ThreadArgs();
    pthread_t host_thread_id = 0;

    if (!thread_args)
        abort();

    thread_args->enc_key = enc_key;
    thread_args->enclave = enclave;

    // Using atomic locks to protect the enclave_host_id_map
    _acquire_lock(&_host_lock);
    enclave_host_id_map.emplace(enc_key, host_thread_id);
    _release_lock(&_host_lock);

    // New Thread is created and executes EnclaveThread
    int ret = pthread_create(&host_thread_id, NULL, EnclaveThread, thread_args);
    if (ret != 0)
    {
        printf("host_create_pthread(): pthread_create error %d\n", ret);
        abort();
    }

    // Main host thread waits for the enclave id to host id mapping to be
    // updated
    while (1)
    {
        _acquire_lock(&_host_lock);
        host_thread_id = enclave_host_id_map[enc_key];
        _release_lock(&_host_lock);
        if (!host_thread_id)
        {
            std::this_thread::sleep_for(std::chrono::microseconds(10 * 1000));
        }
        else
            break;
    }
}

OE_OCALL void host_join_pthread(uint64_t enc_key, oe_enclave_t* enclave)
{
    void* ret;
    pthread_t host_thread_id = 0;

    // Find the host_thread_id from the enclave_host_id_map using the enc_key

    // Using atomic locks to protect the enclave_host_id_map
    _acquire_lock(&_host_lock);
    auto it = enclave_host_id_map.find(enc_key);
    if (it != enclave_host_id_map.end())
    {
        host_thread_id = it->second;
        _release_lock(&_host_lock);

        if (pthread_join(host_thread_id, &ret) != 0)
        {
            printf(
                "pthread_join failed for enclave key=0x%lu, host id=0x%lu\n",
                enc_key,
                it->second);
            abort();
        }
        else
            printf(
                "pthread_join succeeded for enclave id=0x%lu, host id=0x%lu\n",
                enc_key,
                it->second);
    }
    else
    {
        _release_lock(&_host_lock);
        printf(
            "pthread_join failed to find enclave id=0x%lu in host map\n",
            enc_key);
        abort();
    }
}

static int _get_opt(
    int& argc,
    const char* argv[],
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
                    (void*)&argv[i], &argv[i + 1], (argc - i) * sizeof(char*));
                argc--;
                return 1;
            }

            if (i + 1 == argc)
                return -1;

            *arg = argv[i + 1];
            memmove(
                (char**)&argv[i], &argv[i + 2], (argc - i - 1) * sizeof(char*));
            argc -= 2;
            return 1;
        }
    }

    return 0;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;

    // Check for the --sim option:
    if (_get_opt(argc, argv, "--simulate") == 1)
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    else
        flags = oe_get_create_flags();

    // Check argument count:
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    printf("=== %s: %s\n", argv[0], argv[1]);

    // Create the enclave:
    if ((result = oe_create_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    // Invoke "Test()" in the enclave.
    Test(enclave);

    // Shutdown the enclave.
    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
        oe_put_err("oe_terminate_enclave(): result=%u", result);

    printf("\n");

    return 0;
}
