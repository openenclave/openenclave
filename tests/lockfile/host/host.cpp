// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <iostream>
#include <thread>
#include <vector>
#include "../common.h"
#include "lockfile_u.h"

using namespace std;

void thread_routine(oe_enclave_t* enclave)
{
    OE_TEST(test_lockfile_ecall(enclave) == OE_OK);
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_AUTO;
    oe_enclave_t* enc;
    vector<thread> threads;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    /* Create the enclave. */
    result = oe_create_lockfile_enclave(argv[1], type, flags, NULL, 0, &enc);
    OE_TEST(result == OE_OK);

    /* Create threads to call into enclave. */
    {
        threads.reserve(NUM_THREADS);

        for (size_t i = 0; i < NUM_THREADS; i++)
        {
            threads.push_back(thread(thread_routine, enc));
        }
    }

    /* Wait for all threads to finish. */
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        threads[i].join();
    }

    /* Terminate the enclave. */
    OE_TEST(oe_terminate_enclave(enc) == OE_OK);

    return 0;
}
