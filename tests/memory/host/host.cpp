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

#define ITERS 1024
#define BUFSIZE 1024

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

static void _MallocBoundaryTest(oe_enclave_t* enclave, uint32_t flags)
{
    /* Test host malloc boundary. */
    Buffer array[ITERS];
    for (int i = 0; i < ITERS; i++)
    {
        array[i].buf = (unsigned char*)malloc(BUFSIZE);
        OE_TEST(array[i].buf != NULL);
        array[i].size = BUFSIZE;

        OE_TEST(
            oe_call_enclave(enclave, "TestHostBoundaries", &array[i]) == OE_OK);
    }

    for (int i = 0; i < ITERS; i++)
        free(array[i].buf);

    /* Test enclave boundaries. */
    OE_TEST(oe_call_enclave(enclave, "TestEnclaveBoundaries", NULL) == OE_OK);

    /* Test enclave memory across boundaries. */
    unsigned char stackbuf[BUFSIZE];
    for (int i = 0; i < BUFSIZE; i++)
        stackbuf[i] = 1;

    unsigned char* heapbuf = (unsigned char*)malloc(BUFSIZE);
    OE_TEST(heapbuf != NULL);
    for (int i = 0; i < BUFSIZE; i++)
        heapbuf[i] = 2;

    BoundaryArgs args = {
        .hostStack = {.buf = stackbuf, .size = sizeof(stackbuf)},
        .hostHeap = {.buf = heapbuf, .size = BUFSIZE},
    };

    OE_TEST(
        oe_call_enclave(enclave, "TestBetweenEnclaveBoundaries", &args) ==
        OE_OK);

    /* Abort page returns all 0xFFs when accessing. In simulation mode, it's
     * just regular memory. */
    for (size_t i = 0; i < args.enclaveMemory.size; i++)
    {
        if ((flags & OE_ENCLAVE_FLAG_SIMULATE))
            OE_TEST(args.enclaveMemory.buf[i] == 3);
        else
            OE_TEST(args.enclaveMemory.buf[i] == 255);
    }

    for (size_t i = 0; i < args.enclaveHostMemory.size; i++)
        OE_TEST(args.enclaveHostMemory.buf[i] == 4);

    /* Ensure that enclaveMemory still works when passed from the host. */
    OE_TEST(oe_call_enclave(enclave, "TryInputEnclavePointer", &args) == OE_OK);

    /* Cleanup all memory. */
    OE_TEST(oe_call_enclave(enclave, "FreeBoundaryMemory", &args) == OE_OK);
    free(heapbuf);
}

static void _GlobalsTest(oe_enclave_t* enclave)
{
    GlobalArgs args = {.globalInt = 2,
                       .globalFloat = 2.0,
                       .globalPtr = (int*)0x2,
                       .globalStruct = {2, 2},
                       .globalUnion = {.y = 2},
                       .globalArray = {2, 2, 2, 2},
                       .getDefault = 1};

    OE_TEST(oe_call_enclave(enclave, "GetGlobals", &args) == OE_OK);

    /* Verify default global initialization works in the enclave. */
    OE_TEST(args.globalInt == 0);
    OE_TEST(args.globalFloat == 0.0);
    OE_TEST(args.globalPtr == NULL);
    OE_TEST(args.globalStruct.a == 0 && args.globalStruct.b == 0);
    OE_TEST(args.globalUnion.y == 0);
    for (int i = 0; i < GLOBAL_ARRAY_SIZE; i++)
        OE_TEST(args.globalArray[i] == 0);

    /* Verify explicit global initialization works in the enclave. */
    args.getDefault = 0;
    OE_TEST(oe_call_enclave(enclave, "GetGlobals", &args) == OE_OK);
    OE_TEST(args.globalInt == 1);
    OE_TEST(args.globalFloat == 1.0);
    OE_TEST((uintptr_t)args.globalPtr == 0x1);
    OE_TEST(args.globalStruct.a == 1 && args.globalStruct.b == 1);
    OE_TEST(args.globalUnion.y == 1);
    for (int i = 0; i < GLOBAL_ARRAY_SIZE; i++)
        OE_TEST(args.globalArray[i] == 1);

    /* Verify if we can set the globals. */
    GlobalArgs args2 = {.globalInt = 2,
                        .globalFloat = 2.0,
                        .globalPtr = (int*)0x2,
                        .globalStruct = {2, 2},
                        .globalUnion = {.y = 2},
                        .globalArray = {2, 2, 2, 2},
                        .getDefault = 0};

    OE_TEST(oe_call_enclave(enclave, "SetGlobals", &args2) == OE_OK);
    OE_TEST(oe_call_enclave(enclave, "GetGlobals", &args) == OE_OK);

    OE_TEST(args.globalInt == 2);
    OE_TEST(args.globalFloat == 2.0);
    OE_TEST((uintptr_t)args.globalPtr == 0x2);
    OE_TEST(args.globalStruct.a == 2 && args.globalStruct.b == 2);
    OE_TEST(args.globalUnion.y == 2);
    for (int i = 0; i < GLOBAL_ARRAY_SIZE; i++)
        OE_TEST(args.globalArray[i] == 2);
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

    printf("===Starting basic malloc test.\n");
    _MallocBasicTest(enclave);

    printf("===Starting malloc stress test.\n");
    _MallocStressTest(enclave);

    printf("===Starting malloc boundary test.\n");
    _MallocBoundaryTest(enclave, flags);

    printf("===Starting globals test.\n");
    _GlobalsTest(enclave);

    printf("===All tests pass.\n");

    oe_terminate_enclave(enclave);

    return 0;
}
