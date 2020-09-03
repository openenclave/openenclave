// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/advanced/mallinfo.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/tests.h>

#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "memory_t.h"

#define MALLOC_SIZE_SMALL 1024
#define EFFICIENCY_TEST_TIMES 5000000

static size_t _get_heap_size()
{
    oe_mallinfo_t info;
    oe_result_t rc = oe_allocator_mallinfo(&info);
    OE_TEST(rc == OE_OK);
    return info.current_allocated_heap_size;
}

static int _malloc_free_fixed_size(size_t size, int times)
{
    int i = 0;
    int* buffer = NULL;

    for (i = 0; i < times; i++)
    {
        buffer = (int*)malloc(size);
        if (NULL == buffer)
        {
            return -1;
        }
        free(buffer);
    }

    oe_host_printf("_malloc_free_fixed_size malloc times = %d.\n", i);
    return 0;
}

static inline size_t _randx(size_t x)
{
    /* Note that rand() % N is biased if RAND_MAX + 1 isn't divisible
     * by N. But, slight probability bias doesn't really matter in these
     * tests. */
    return (size_t)rand() % x;
}

/*
 * Test making `times` allocations of random sizes.
 * If seed is < 0 just use time() as a seed. If seed >= 0, use the provided
 * to seed the rng.
 */
static int _malloc_free_random_size(int times, unsigned int seed)
{
    int i = 0;
    size_t size = 0;
    void* buffer = NULL;

    oe_host_printf("_malloc_free_random_size seed = %d\n", seed);
    srand(seed);
    for (i = 0; i < times; i++)
    {
        size = _randx(_get_heap_size());
        buffer = malloc(size);
        if (NULL == buffer)
        {
            return -1;
        }

        free(buffer);
    }
    oe_host_printf("_malloc_free_random_size malloc times = %d.\n", i);
    return 0;
}

void test_malloc_fixed_size_fragment(void)
{
    oe_use_debug_malloc_memset = false;

    // get heap size before tests
    size_t heap_size_before_test = _get_heap_size();
    oe_host_printf(
        "[test_malloc_fixed_size_fragment]heap size before test : %zu.\n",
        heap_size_before_test);

    OE_TEST(
        _malloc_free_fixed_size(MALLOC_SIZE_SMALL, EFFICIENCY_TEST_TIMES) == 0);

    size_t heap_size_after_test = _get_heap_size();
    oe_host_printf(
        "[test_malloc_fixed_size_fragment]heap size after test : %zu.\n",
        heap_size_after_test);
    OE_TEST(heap_size_before_test == heap_size_after_test);

    oe_use_debug_malloc_memset = true;
}

void test_malloc_random_size_fragment(unsigned int seed)
{
    oe_use_debug_malloc = false;

    // get heap size before tests
    size_t heap_size_before_test = _get_heap_size();
    oe_host_printf(
        "[test_malloc_random_size_fragment]heap size before test : %zu.\n",
        heap_size_before_test);

    OE_TEST(_malloc_free_random_size(EFFICIENCY_TEST_TIMES, seed) == 0);

    size_t heap_size_after_test = _get_heap_size();
    oe_host_printf(
        "[test_malloc_random_size_fragment]heap size after test : %zu.\n",
        heap_size_after_test);
    OE_TEST(heap_size_before_test == heap_size_after_test);

    oe_use_debug_malloc = true;
}
