// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <time.h>
#include <cstdio>
#include <thread>
#include <vector>

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/tests.h>

#include "memory_u.h"

#define ITERS 1024
#define BUFSIZE 1024

static void _malloc_basic_test(oe_enclave_t* enclave)
{
    OE_TEST(test_malloc(enclave) == OE_OK);
    OE_TEST(test_calloc(enclave) == OE_OK);
    OE_TEST(test_realloc(enclave) == OE_OK);
    OE_TEST(test_memalign(enclave) == OE_OK);
    OE_TEST(test_posix_memalign(enclave) == OE_OK);
    OE_TEST(test_malloc_usable_size(enclave) == OE_OK);
}

static void _malloc_stress_test_single_thread(
    oe_enclave_t* enclave,
    int thread_num)
{
    OE_TEST(malloc_stress_test(enclave, thread_num) == OE_OK);
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
    OE_TEST(init_malloc_stress_test(enclave) == OE_OK);
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

        OE_TEST(test_host_boundaries(enclave, array[i]) == OE_OK);
    }

    for (int i = 0; i < ITERS; i++)
        free(array[i].buf);

    /* Test enclave boundaries. */
    OE_TEST(test_enclave_boundaries(enclave) == OE_OK);

    /* Test enclave memory across boundaries. */
    unsigned char stackbuf[BUFSIZE];
    for (int i = 0; i < BUFSIZE; i++)
        stackbuf[i] = 1;

    unsigned char* heapbuf = (unsigned char*)malloc(BUFSIZE);
    OE_TEST(heapbuf != NULL);
    for (int i = 0; i < BUFSIZE; i++)
        heapbuf[i] = 2;

    buffer host_stack;
    buffer host_heap;
    buffer enclave_memory;
    buffer enclave_host_memory;

    host_stack.buf = stackbuf;
    host_stack.size = sizeof(stackbuf);
    host_heap.buf = heapbuf;
    host_heap.size = BUFSIZE;

    OE_TEST(
        test_between_enclave_boundaries(
            enclave,
            host_stack,
            host_heap,
            &enclave_memory,
            &enclave_host_memory) == OE_OK);

    /* Abort page returns all 0xFFs when accessing. In simulation mode, it's
     * just regular memory. */
    for (size_t i = 0; i < enclave_memory.size; i++)
    {
        if ((flags & OE_ENCLAVE_FLAG_SIMULATE))
            OE_TEST(enclave_memory.buf[i] == 3);
        else
            OE_TEST(enclave_memory.buf[i] == 255);
    }

    for (size_t i = 0; i < enclave_host_memory.size; i++)
        OE_TEST(enclave_host_memory.buf[i] == 4);

    /* Ensure that enclave_memory still works when passed from the host. */
    OE_TEST(try_input_enclave_pointer(enclave, enclave_memory) == OE_OK);

    /* Cleanup all memory. */
    OE_TEST(
        free_boundary_memory(enclave, enclave_memory, enclave_host_memory) ==
        OE_OK);
    free(heapbuf);
}

#if !defined(OE_USE_DEBUG_MALLOC)
static void _malloc_fixed_size_fragment_test(oe_enclave_t* enclave)
{
    test_malloc_fixed_size_fragment(enclave);
}

static void _malloc_random_size_fragment_test(oe_enclave_t* enclave, int seed)
{
    unsigned int chosen_seed;

    if (seed < 0)
    {
        chosen_seed = (unsigned int)time(NULL);
    }
    else
    {
        chosen_seed = (unsigned int)seed;
    }
    test_malloc_random_size_fragment(enclave, chosen_seed);
}
#endif

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    result = oe_create_memory_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    printf("===Starting basic malloc test.\n");
    _malloc_basic_test(enclave);

    printf("===Starting malloc stress test.\n");
    _malloc_stress_test(enclave);

    printf("===Starting malloc boundary test.\n");
    _malloc_boundary_test(enclave, flags);

#if !defined(OE_USE_DEBUG_MALLOC)
    printf("===Starting malloc fixed size fragment test.\n");
    _malloc_fixed_size_fragment_test(enclave);

    printf("===Starting malloc random size fragment test.\n");
    int seed = -1;
    if (argc > 2)
    {
        // Try to parse seed passed from command-line
        int len = (int)strlen(argv[2]);
        char* endptr = NULL;
        seed = (int)strtol(argv[2], &endptr, 10);
        if (endptr - argv[2] != len)
        {
            fprintf(stderr, "%s is not a valid seed\n", argv[2]);
            return 1;
        }
    }
    _malloc_random_size_fragment_test(enclave, seed);
#endif

    printf("===All tests pass.\n");

    oe_terminate_enclave(enclave);

    return 0;
}
