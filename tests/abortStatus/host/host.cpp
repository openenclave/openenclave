// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>
#include "abortStatus_u.h"

#define THREAD_COUNT 3

typedef oe_result_t (*enc_fn)(oe_enclave_t*, int*);

void foobar()
{
    oe_put_err("Error: unreachable code is reached.\n");
}

void TestAbortStatus(
    oe_enclave_t* enclave,
    const char* function_name,
    enc_fn function)
{
    printf("=== %s(%s)  \n", __FUNCTION__, function_name);
    int rval = 0;
    oe_result_t result = function(enclave, &rval);

    OE_TEST(result == OE_ENCLAVE_ABORTING);
    OE_TEST(0 == rval);
}

static void CrashEnclaveThread(
    oe_enclave_t* enclave,
    std::atomic<uint32_t>* thread_ready_count,
    std::atomic<bool>* is_enclave_crashed,
    enc_fn ecall_function)
{
    // Wait all worker threads ready.
    while (thread_ready_count->load() != (THREAD_COUNT - 1))
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Crash the enclave to set enclave in abort status.
    int rval = 0;
    oe_result_t result = ecall_function(enclave, &rval);
    OE_TEST(result == OE_ENCLAVE_ABORTING);
    OE_TEST(0 == rval);

    // Release all worker threads.
    *is_enclave_crashed = true;
    return;
}

static void EcallAfterCrashThread(
    oe_enclave_t* enclave,
    std::atomic<uint32_t>* thread_ready_count,
    std::atomic<bool>* is_enclave_crashed)
{
    ++(*thread_ready_count);

    // Wait until the enclave is aborted.
    while (!(*is_enclave_crashed))
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Try to ECALL into the enclave.
    int rval = -1;
    oe_result_t result = normal_ecall(enclave, &rval);
    OE_TEST(result == OE_ENCLAVE_ABORTING);
    OE_TEST(-1 == rval);
    return;
}

static void OcallAfterCrashThread(
    oe_enclave_t* enclave,
    std::atomic<uint32_t>* thread_ready_count,
    std::atomic<bool>* is_enclave_crashed)
{
    int rval = 0;
    void* _thread_ready_count = reinterpret_cast<void*>(thread_ready_count);
    void* _is_enclave_crashed = reinterpret_cast<void*>(is_enclave_crashed);
    oe_result_t result = test_ocall_after_abort(
        enclave, &rval, _thread_ready_count, _is_enclave_crashed);
    OE_TEST(result == OE_OK);
    OE_TEST(0 == rval);

    return;
}

// Test the regular abort case and un-handled hardware exception case in
// single thread.
static bool TestBasicAbort(const char* enclave_name)
{
    const uint32_t flags = oe_get_create_flags();

    std::pair<char const*, enc_fn> functions[] = {
        std::make_pair("regular_abort", regular_abort),
        std::make_pair(
            "generate_unhandled_hardware_exception",
            generate_unhandled_hardware_exception),
    };

    for (uint32_t i = 0; i < OE_COUNTOF(functions); ++i)
    {
        oe_enclave_t* enclave = NULL;
        oe_result_t result = oe_create_abortStatus_enclave(
            enclave_name, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
        if (OE_OK != result)
        {
            oe_put_err("oe_create_abortStatus_enclave(): result=%u", result);
            return false;
        }

        // Skip the last test for simulation mode.
        if ((flags & OE_ENCLAVE_FLAG_SIMULATE) == 0 ||
            (i != OE_COUNTOF(functions) - 1))
        {
            TestAbortStatus(enclave, functions[i].first, functions[i].second);
        }

        // Enclave should be terminated correctly but there are no guarantees
        // that all memory will be freed after enclave has been aborted
        result = oe_terminate_enclave(enclave);
        if ((result != OE_MEMORY_LEAK) && (result != OE_OK))
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
    // Create the enclave.
    const uint32_t flags = oe_get_create_flags();
    std::vector<enc_fn> functions = {regular_abort};

    // Only run hardware exception test on non-simulated mode.
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) == 0)
    {
        functions.push_back(generate_unhandled_hardware_exception);
    }

    for (enc_fn function : functions)
    {
        oe_enclave_t* enclave = nullptr;
        oe_result_t result = oe_create_abortStatus_enclave(
            enclave_name, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

        if (OE_OK != result)
        {
            oe_put_err("oe_create_abortStatus_enclave(): result=%u", result);
            return false;
        }

        // Create threads.
        std::vector<std::thread> threads;
        std::atomic<uint32_t> thread_ready_count(0);
        std::atomic<bool> is_enclave_crashed(false);

        threads.push_back(std::thread(
            CrashEnclaveThread,
            enclave,
            &thread_ready_count,
            &is_enclave_crashed,
            *function));

        threads.push_back(std::thread(
            EcallAfterCrashThread,
            enclave,
            &thread_ready_count,
            &is_enclave_crashed));

        threads.push_back(std::thread(
            OcallAfterCrashThread,
            enclave,
            &thread_ready_count,
            &is_enclave_crashed));

        // All threads must exit gracefully.
        for (auto& t : threads)
        {
            t.join();
        }

        // Enclave should be terminated correctly but there are no guarantees
        // that all memory will be freed after enclave has been aborted
        result = oe_terminate_enclave(enclave);
        if ((result != OE_MEMORY_LEAK) && (result != OE_OK))
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
