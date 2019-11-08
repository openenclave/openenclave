// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>
#include "create_rapid_u.h"

#define MAX_ENCLAVES 200
#define MAX_SIMULTANEOUS_ENCLAVES 32
#define MAX_THREADS 32

static void _launch_enclave(const char* path, uint32_t flags, bool call_enclave)
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    result = oe_create_create_rapid_enclave(
        path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result != OE_OK)
        oe_put_err("oe_create_create_rapid_enclave(): result=%u", result);

    if (call_enclave)
    {
        int arg = 123;
        int return_value;
        if ((result = test(enclave, &return_value, arg)) != OE_OK)
        {
            oe_terminate_enclave(enclave);
            oe_put_err("test(): result=%u", result);
        }
        OE_TEST(return_value == 246);
    }

    result = oe_terminate_enclave(enclave);
    if (result != OE_OK)
        oe_put_err("oe_terminate_enclave(): result=%u", result);
}

static void _test_sequential(
    const char* path,
    uint32_t flags,
    bool call_enclave)
{
    for (int i = 0; i < MAX_ENCLAVES; i++)
    {
        _launch_enclave(path, flags, call_enclave);
    }
}

static void _test_simultaneous(
    const char* path,
    uint32_t flags,
    bool call_enclave)
{
    oe_enclave_t* enclaves[MAX_SIMULTANEOUS_ENCLAVES];
    oe_result_t result = OE_OK;

    int num_enclaves = 0;
    for (; num_enclaves < MAX_SIMULTANEOUS_ENCLAVES; num_enclaves++)
    {
        result = oe_create_create_rapid_enclave(
            path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclaves[num_enclaves]);

        if (result != OE_OK)
        {
            fprintf(
                stderr,
                "oe_create_create_rapid_enclave(): result=%u, iter=%u",
                result,
                num_enclaves);

            goto Cleanup;
        }
    }

    if (call_enclave)
    {
        for (int i = 0; i < num_enclaves; i++)
        {
            int arg = i;
            int return_value;
            result = test(enclaves[i], &return_value, arg);

            if (result != OE_OK)
            {
                fprintf(stderr, "test(): result=%u, iter=%u", result, i);

                goto Cleanup;
            }

            // This is an arbitrary test validation that the enclave
            // call behaves this way
            OE_TEST(return_value == 2 * i);
        }
    }

Cleanup:
    for (int i = 0; i < num_enclaves; i++)
    {
        oe_result_t terminate_result = oe_terminate_enclave(enclaves[i]);
        if (terminate_result != OE_OK)
        {
            // Log that there was an error, but continue termination.
            result = terminate_result;

            fprintf(
                stderr,
                "oe_terminate_enclave(): result=%u, iter=%u",
                result,
                i);
        }
    }

    // Fail the test if any of the functions failed.
    if (result != OE_OK)
        oe_put_err("_test_simultaneous failed");
}

static void _test_multithreaded(
    const char* path,
    uint32_t flags,
    bool call_enclave)
{
    std::vector<std::thread> threads;

    for (int i = 0; i < MAX_THREADS; i++)
    {
        threads.emplace_back(
            std::thread(_launch_enclave, path, flags, call_enclave));
    }

    for (auto& thread : threads)
        thread.join();
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    // Test rapid enclave creation sequentially.
    _test_sequential(argv[1], flags, false);
    _test_sequential(argv[1], flags, true);

    // Test rapid enclave creation simultaneously.
    _test_simultaneous(argv[1], flags, false);
    _test_simultaneous(argv[1], flags, true);

    // Test multi-threaded enclave creation.
    _test_multithreaded(argv[1], flags, false);
    _test_multithreaded(argv[1], flags, true);

    return 0;
}
