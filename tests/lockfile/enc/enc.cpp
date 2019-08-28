// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <iostream>
#include "../common.h"
#include "lockfile_t.h"

using namespace std;

extern "C" void test_lockfile_ecall(void)
{
    const size_t NUM_ITERATIONS = 4000;

    for (size_t i = 0; i < NUM_ITERATIONS; i++)
    {
        cout << "test_lockfile_ecall()" << endl;
    }
}

OE_SET_ENCLAVE_SGX(
    1,            /* ProductID */
    1,            /* SecurityVersion */
    true,         /* AllowDebug */
    1024,         /* HeapPageCount */
    1024,         /* StackPageCount */
    NUM_THREADS); /* TCSCount */
