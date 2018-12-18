// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread>
#include "thread_local_u.h"

#define SKIP_RETURN_CODE 2

void run_enclave_thread(
    oe_enclave_t* enclave,
    int thread_num,
    int iters,
    int step)
{
    OE_TEST(enclave_thread(enclave, thread_num, iters, step) == OE_OK);
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf(
            "=== Skipped unsupported test in simulation mode "
            "(thread-local)\n");
        return SKIP_RETURN_CODE;
    }

    if ((result = oe_create_thread_local_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    // Run it twice to make sure the enclave thread is correctly reinitialized.
    for (int i = 0; i < 2; ++i)
    {
        // Clear test data in the enclave.
        OE_TEST(clear_test_data(enclave) == OE_OK);

        std::thread t1(run_enclave_thread, enclave, 1, 1000, 3);
        std::thread t2(run_enclave_thread, enclave, 2, 1000, 7);

        t1.join();
        t2.join();
    }

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (thread-local)\n");

    return 0;
}
