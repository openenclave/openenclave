// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>

#define MAX_ENCLAVES 200
#define MAX_SIMULTANEOUS_ENCLAVES 32
#define MAX_THREADS 32

static void _LaunchEnclave(const char* path, uint32_t flags, bool call_enclave)
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    result =
        oe_create_enclave(path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    if (call_enclave)
    {
        int arg = 123;
        if ((result = oe_call_enclave(enclave, "Test", &arg)) != OE_OK)
        {
            oe_terminate_enclave(enclave);
            oe_put_err("oe_call_enclave(): result=%u", result);
        }
        OE_TEST(arg == 246);
    }

    result = oe_terminate_enclave(enclave);
    if (result != OE_OK)
        oe_put_err("oe_terminate_enclave(): result=%u", result);
}

static void _TestSequential(const char* path, uint32_t flags, bool call_enclave)
{
    for (int i = 0; i < MAX_ENCLAVES; i++)
    {
        _LaunchEnclave(path, flags, call_enclave);
    }
}

static void _TestSimultaneous(
    const char* path,
    uint32_t flags,
    bool call_enclave)
{
    oe_enclave_t* enclaves[MAX_SIMULTANEOUS_ENCLAVES];
    oe_result_t result = OE_OK;

    int numEnclaves = 0;
    for (; numEnclaves < MAX_SIMULTANEOUS_ENCLAVES; numEnclaves++)
    {
        result = oe_create_enclave(
            path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclaves[numEnclaves]);

        if (result != OE_OK)
        {
            fprintf(
                stderr,
                "oe_create_enclave(): result=%u, iter=%u",
                result,
                numEnclaves);

            goto Cleanup;
        }
    }

    if (call_enclave)
    {
        for (int i = 0; i < numEnclaves; i++)
        {
            int args = i;
            result = oe_call_enclave(enclaves[i], "Test", &args);

            if (result != OE_OK)
            {
                fprintf(
                    stderr, "oe_call_enclave(): result=%u, iter=%u", result, i);

                goto Cleanup;
            }

            // This is an arbitrary test validation that the enclave
            // call behaves this way
            OE_TEST(args == 2 * i);
        }
    }

Cleanup:
    for (int i = 0; i < numEnclaves; i++)
    {
        oe_result_t terminateResult = oe_terminate_enclave(enclaves[i]);
        if (terminateResult != OE_OK)
        {
            // Log that there was an error, but continue termination.
            result = terminateResult;

            fprintf(
                stderr,
                "oe_terminate_enclave(): result=%u, iter=%u",
                result,
                i);
        }
    }

    // Fail the test if any of the functions failed.
    if (result != OE_OK)
        oe_put_err("_TestSimultaneous failed");
}

static void _TestMultiThreaded(
    const char* path,
    uint32_t flags,
    bool call_enclave)
{
    std::vector<std::thread> threads;

    for (int i = 0; i < MAX_THREADS; i++)
    {
        threads.emplace_back(
            std::thread(_LaunchEnclave, path, flags, call_enclave));
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
    _TestSequential(argv[1], flags, false);
    _TestSequential(argv[1], flags, true);

    // Test rapid enclave creation simultaneously.
    _TestSimultaneous(argv[1], flags, false);
    _TestSimultaneous(argv[1], flags, true);

    // Test multi-threaded enclave creation.
    _TestMultiThreaded(argv[1], flags, false);
    _TestMultiThreaded(argv[1], flags, true);

    return 0;
}
