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
#include "../args.h"
#include "args.h"
#include "ocalls.h"

// Host maintains a map of enclave to host thread ID
static std::map<pthread_t, pthread_t> enclave_host_id_map;
static pthread_t host_thread_id;

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
    oe_enclave_t* enclave = (oe_enclave_t*)args;

    oe_result_t result = oe_call_enclave(enclave, "_EnclaveLaunchThread", NULL);
    OE_TEST(result == OE_OK);

    return NULL;
}

OE_OCALL void host_create_pthread(void* arg, oe_enclave_t* enclave)
{
    pthread_t* enc_id = (pthread_t*)arg;

    // New Thread is created and executes EnclaveThread
    pthread_create(&host_thread_id, NULL, EnclaveThread, enclave);

    // Main host thread continues - update the enclave id to host id mapping
    printf(
        "host_create_pthread(): Enc id=%lu has Host id of 0x%lu\n",
        *enc_id,
        host_thread_id);
    enclave_host_id_map.emplace(*enc_id, host_thread_id);
}

OE_OCALL void host_join_pthread(void* arg, oe_enclave_t* enclave)
{
    pthread_t* enc_id = (pthread_t*)arg;
    void* ret;

    /* Find the host_thread_id from the enc_id */
    std::map<pthread_t, pthread_t>::iterator it;
    it = enclave_host_id_map.find(*enc_id);
    if (it != enclave_host_id_map.end())
    {
        if (pthread_join(it->second, &ret) != 0)
        {
            printf("pthread_join failed for 0x%lu\n", it->second);
            abort();
        }
    }
}

static int _GetOpt(
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
    if (_GetOpt(argc, argv, "--simulate") == 1)
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
