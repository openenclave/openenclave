// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdio>
#include <cstdlib>
#include <cstdlib>
#include <thread>
#include <vector>
#include "../args.h"

using namespace std;

#define THREAD_COUNT 3

void TestAbortStatus(oe_enclave_t* enclave, const char* function_name)
{
    oe_result_t result;
    AbortStatusArgs args;
    args.ret = -1;

    printf("=== %s(%s)  \n", __FUNCTION__, function_name);
    result = oe_call_enclave(enclave, function_name, &args);
    OE_TEST(result == OE_ENCLAVE_ABORTING);
    OE_TEST(args.ret == 0);
}

static void CrashEnclaveThread(
    oe_enclave_t* enclave,
    std::atomic<uint32_t>* thread_ready_count,
    std::atomic<bool>* is_enclave_crashed,
    const char* ecall_function)
{
    oe_result_t result;
    AbortStatusArgs args;
    args.ret = -1;
    args.thread_ready_count = thread_ready_count;
    args.is_enclave_crashed = is_enclave_crashed;

    // Wait all worker threads ready.
    while (*args.thread_ready_count != THREAD_COUNT - 1)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Crash the enclave to set enclave in abort status.
    result = oe_call_enclave(enclave, ecall_function, &args);
    OE_TEST(result == OE_ENCLAVE_ABORTING);
    OE_TEST(args.ret == 0);

    // Release all worker threads.
    *args.is_enclave_crashed = 1;
    return;
}

static void EcallAfterCrashThread(
    oe_enclave_t* enclave,
    std::atomic<uint32_t>* thread_ready_count,
    std::atomic<bool>* is_enclave_crashed)
{
    oe_result_t result;
    AbortStatusArgs args;
    args.ret = -1;
    args.thread_ready_count = thread_ready_count;
    args.is_enclave_crashed = is_enclave_crashed;

    ++*args.thread_ready_count;

    // Wait the enclave is aborted.
    while (*args.is_enclave_crashed == 0)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Try to ECALL into the enclave.
    result = oe_call_enclave(enclave, "NormalECall", &args);
    OE_TEST(result == OE_ENCLAVE_ABORTING);
    OE_TEST(args.ret == -1);
    return;
}

static void OcallAfterCrashThread(
    oe_enclave_t* enclave,
    std::atomic<uint32_t>* thread_ready_count,
    std::atomic<bool>* is_enclave_crashed)
{
    oe_result_t result;
    AbortStatusArgs args;
    args.ret = -1;
    args.thread_ready_count = thread_ready_count;
    args.is_enclave_crashed = is_enclave_crashed;

    result = oe_call_enclave(enclave, "TestOCallAfterAbort", &args);
    OE_TEST(result == OE_OK);
    OE_TEST(args.ret == 0);

    return;
}
// Test the regular abort case and un-handled hardware exception case in
// single thread.
static bool TestBasicAbort(const char* enclave_name)
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    const uint32_t flags = oe_get_create_flags();
    const char* function_names[] = {"RegularAbort",
                                    "GenerateUnhandledHardwareException"};

    for (uint32_t i = 0; i < OE_COUNTOF(function_names); i++)
    {
        if ((result = oe_create_enclave(
                 enclave_name,
                 OE_ENCLAVE_TYPE_SGX,
                 flags,
                 NULL,
                 0,
                 NULL,
                 0,
                 &enclave)) != OE_OK)
        {
            oe_put_err("oe_create_enclave(): result=%u", result);
            return false;
        }

        // Skip the last test for simulation mode.
        if ((flags & OE_ENCLAVE_FLAG_SIMULATE) == 0 ||
            (i != OE_COUNTOF(function_names) - 1))
        {
            TestAbortStatus(enclave, function_names[i]);
        }

        if ((result = oe_terminate_enclave(enclave)) != OE_OK)
        {
            oe_put_err("oe_terminate_enclave(): result=%u", result);
            return false;
        }
    }

    return true;
}

// Test enclave abort status in multiple threads.
// Thread 1 -> abort the enclave when all other threads are ready.
// Thread 2 -> do a ECALL after thread 1 abort the enclave. The ECALL should
//  fail with abort status.
// Thread 3 -> do an OCALL after thread 1 abort the enclave. The OCALL should
//  fail with abort status.
static bool TestMultipleThreadAbort(const char* enclave_name)
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    // Create the enclave.
    const uint32_t flags = oe_get_create_flags();
    vector<string> function_names{"RegularAbort"};

    // Only run hardware exception test on non-simulated mode.
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) == 0)
    {
        function_names.push_back("GenerateUnhandledHardwareException");
    }

    for (uint32_t i = 0; i < function_names.size(); i++)
    {
        if ((result = oe_create_enclave(
                 enclave_name,
                 OE_ENCLAVE_TYPE_SGX,
                 flags,
                 NULL,
                 0,
                 NULL,
                 0,
                 &enclave)) != OE_OK)
        {
            oe_put_err("oe_create_enclave(): result=%u", result);
            return false;
        }

        // Create threads.
        std::vector<std::thread> threads;
        std::atomic<uint32_t> thread_ready_count(0);
        std::atomic<bool> is_enclave_crashed(0);

        threads.push_back(
            std::thread(
                CrashEnclaveThread,
                enclave,
                &thread_ready_count,
                &is_enclave_crashed,
                function_names[i].c_str()));

        threads.push_back(
            std::thread(
                EcallAfterCrashThread,
                enclave,
                &thread_ready_count,
                &is_enclave_crashed));

        threads.push_back(
            std::thread(
                OcallAfterCrashThread,
                enclave,
                &thread_ready_count,
                &is_enclave_crashed));

        // All threads must exit gracefully.
        for (auto& t : threads)
        {
            t.join();
        }

        // Enclave should be terminated correctly.
        if ((result = oe_terminate_enclave(enclave)) != OE_OK)
        {
            oe_put_err("oe_terminate_enclave(): result=%u", result);
            return false;
        }
    }

    return true;
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    printf("=== This program is used to test enclave abort status.\n");

    if (TestBasicAbort(argv[1]))
    {
        printf("Basic abort status tests passed.\n");
    }
    else
    {
        oe_put_err("Basic abort status tests failed.\n");
        return 1;
    }

    if (TestMultipleThreadAbort(argv[1]))
    {
        printf("Multiple threads abort status tests passed.\n");
    }
    else
    {
        oe_put_err("Multiple threads abort status tests failed.\n");
        return 1;
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
