// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <cstdio>
#include <thread>
#include <vector>

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/tests.h>

#include "../args.h"

static void _MallocBasicTest(oe_enclave_t* enclave)
{
    OE_TEST(oe_call_enclave(enclave, "TestMalloc", NULL) == OE_OK);
    OE_TEST(oe_call_enclave(enclave, "TestCalloc", NULL) == OE_OK);
    OE_TEST(oe_call_enclave(enclave, "TestRealloc", NULL) == OE_OK);
    OE_TEST(oe_call_enclave(enclave, "TestMemalign", NULL) == OE_OK);
    OE_TEST(oe_call_enclave(enclave, "TestPosixMemalign", NULL) == OE_OK);
}

static void _MallocStressTestSingleThread(oe_enclave_t* enclave, int threadNum)
{
    MallocStressTestArgs args = {threadNum};
    OE_TEST(oe_call_enclave(enclave, "MallocStressTest", &args) == OE_OK);
}

static void _MallocStressTestMultiThread(oe_enclave_t* enclave)
{
    std::vector<std::thread> vec;
    for (int i = 0; i < 4; i++)
        vec.push_back(std::thread(_MallocStressTestSingleThread, enclave, 4));

    for (auto& t : vec)
        t.join();
}

static void _MallocStressTest(oe_enclave_t* enclave)
{
    OE_TEST(oe_call_enclave(enclave, "InitMallocStressTest", NULL) == OE_OK);
    _MallocStressTestSingleThread(enclave, 1);
    _MallocStressTestMultiThread(enclave);
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

    result = oe_create_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    _MallocBasicTest(enclave);
    _MallocStressTest(enclave);

    oe_terminate_enclave(enclave);

    return 0;
}
