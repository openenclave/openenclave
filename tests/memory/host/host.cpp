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

static void _malloc_basic_test(oe_enclave_t* enclave)
{
    OE_TEST(oe_call_enclave(enclave, "test_malloc", NULL) == OE_OK);
    OE_TEST(oe_call_enclave(enclave, "test_calloc", NULL) == OE_OK);
    OE_TEST(oe_call_enclave(enclave, "test_realloc", NULL) == OE_OK);
    OE_TEST(oe_call_enclave(enclave, "test_memalign", NULL) == OE_OK);
    OE_TEST(oe_call_enclave(enclave, "test_posix_memalign", NULL) == OE_OK);
}

static void _malloc_stress_test_single_thread(
    oe_enclave_t* enclave,
    int thread_num)
{
    malloc_stress_test_args args = {thread_num};
    OE_TEST(oe_call_enclave(enclave, "malloc_stress_test", &args) == OE_OK);
}

static void _malloc_stress_test_multithread(oe_enclave_t* enclave)
{
    std::vector<std::thread> vec;
    for (int i = 0; i < 4; i++)
        vec.push_back(
            std::thread(_malloc_stress_test_single_thread, enclave, 4));

    for (auto& t : vec)
        t.join();
}

static void _malloc_stress_test(oe_enclave_t* enclave)
{
    OE_TEST(oe_call_enclave(enclave, "init_malloc_stress_test", NULL) == OE_OK);
    _malloc_stress_test_single_thread(enclave, 1);
    _malloc_stress_test_multithread(enclave);
}

static void _malloc_boundary_test(oe_enclave_t* enclave, uint32_t flags)
{
    /* Test host malloc boundary. */
    buffer array[ITERS];
    for (int i = 0; i < ITERS; i++)
    {
        array[i].buf = (unsigned char*)malloc(BUFSIZE);
        OE_TEST(array[i].buf != NULL);
        array[i].size = BUFSIZE;

        OE_TEST(
            oe_call_enclave(enclave, "test_host_boundaries", &array[i]) ==
            OE_OK);
    }

    for (int i = 0; i < ITERS; i++)
        free(array[i].buf);

    /* Test enclave boundaries. */
    OE_TEST(oe_call_enclave(enclave, "test_enclave_boundaries", NULL) == OE_OK);

    /* Test enclave memory across boundaries. */
    unsigned char stackbuf[BUFSIZE];
    for (int i = 0; i < BUFSIZE; i++)
        stackbuf[i] = 1;

    unsigned char* heapbuf = (unsigned char*)malloc(BUFSIZE);
    OE_TEST(heapbuf != NULL);
    for (int i = 0; i < BUFSIZE; i++)
        heapbuf[i] = 2;

    boundary_args args = {
        .host_stack = {.buf = stackbuf, .size = sizeof(stackbuf)},
        .host_heap = {.buf = heapbuf, .size = BUFSIZE},
    };

    OE_TEST(
        oe_call_enclave(enclave, "test_between_enclave_boundaries", &args) ==
        OE_OK);

    /* Abort page returns all 0xFFs when accessing. In simulation mode, it's
     * just regular memory. */
    for (size_t i = 0; i < args.enclave_memory.size; i++)
    {
        if ((flags & OE_ENCLAVE_FLAG_SIMULATE))
            OE_TEST(args.enclave_memory.buf[i] == 3);
        else
            OE_TEST(args.enclave_memory.buf[i] == 255);
    }

    for (size_t i = 0; i < args.enclave_host_memory.size; i++)
        OE_TEST(args.enclave_host_memory.buf[i] == 4);

    /* Ensure that enclave_memory still works when passed from the host. */
    OE_TEST(
        oe_call_enclave(enclave, "try_input_enclave_pointer", &args) == OE_OK);

    /* Cleanup all memory. */
    OE_TEST(oe_call_enclave(enclave, "free_boundary_memory", &args) == OE_OK);
    free(heapbuf);
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
    _malloc_basic_test(enclave);

    printf("===Starting malloc stress test.\n");
    _malloc_stress_test(enclave);

    printf("===Starting malloc boundary test.\n");
    _malloc_boundary_test(enclave, flags);

    printf("===All tests pass.\n");

    oe_terminate_enclave(enclave);

    return 0;
}
