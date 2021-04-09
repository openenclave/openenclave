// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/tests.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "memory_t.h"

#define ITERS 1000
#define OE_USED_HEAP 20584 /* Amount of heap consumed by OE. */

/* We have two frees so that the number of frees is balanced with the ones
 * that allocate memory (malloc and calloc). */
#define TEST_MALLOC 0
#define TEST_CALLOC 1
#define TEST_REALLOC 2
#define TEST_FREE_0 3
#define TEST_FREE_1 4
#define TEST_SET_VAL 5
#define TEST_GET_VAL 6
#define NUM_TESTS 7

static inline size_t _randx(size_t x)
{
    /* Note that rand() % N is biased if RAND_MAX + 1 isn't divisible
     * by N. But, slight probability bias doesn't really matter in these
     * tests. */
    return (size_t)rand() % x;
}

static inline size_t _min(size_t x, size_t y)
{
    return (x < y) ? x : y;
}

static size_t _get_alloc_size(size_t max_size)
{
#if NO_PAGING_SUPPORT
    /*
     * Simple distribution to test varied memory allocation:
     *  - 30% of the time pick 0 <= x < 64 bytes.
     *  - 40% of the time pick 64 <= x <= 4K bytes.
     *  - 30% of the time pick 4K <= x <= 256K bytes.
     */
    size_t val = _randx(100);
    if (val < 30)
        return _min(_randx(64), max_size);
    else if (val < 70)
        return _min(_randx(4096), max_size);
    else
        return _min(_randx(256 * 1024), max_size);
#else
    /*
     * Simple distribution to test varied memory allocation:
     *  - 20% of the time pick 0 <= x < 64 bytes.
     *  - 30% of the time pick 64 <= x <= 4K bytes.
     *  - 30% of the time pick 4K <= x <= 256K bytes.
     *  - 20% of the time pick 256K <= x < 16MB bytes.
     */
    size_t val = _randx(100);
    if (val < 20)
        return _min(_randx(64), max_size);
    else if (val < 50)
        return _min(_randx(4096), max_size);
    else if (val < 80)
        return _min(_randx(256 * 1024), max_size);
    else
        return _min(_randx(16 * 1024 * 1024), max_size);
#endif
}

static void _handle_alloc(
    buffer* buf,
    int action,
    int* index_,
    size_t* max_size_)
{
    size_t index = (size_t)*index_;
    size_t max_size = *max_size_;
    size_t to_alloc = _get_alloc_size(max_size);

    switch (action)
    {
        /* For malloc/calloc, we add the new memory block to buffer array. */
        case TEST_MALLOC:
            buf[index].buf = (unsigned char*)malloc(to_alloc);
            buf[index].size = to_alloc;
            OE_TEST(buf[index].buf != NULL);
            max_size -= to_alloc;
            index++;
            break;
        case TEST_CALLOC:
            buf[index].buf = (unsigned char*)calloc(1, to_alloc);
            buf[index].size = to_alloc;
            OE_TEST(buf[index].buf != NULL);
            max_size -= to_alloc;
            index++;
            break;

        /* For realloc, we change the last allocated block. */
        case TEST_REALLOC:
            max_size += buf[index - 1].size;
            buf[index - 1].buf =
                (unsigned char*)realloc(buf[index - 1].buf, to_alloc);
            buf[index - 1].size = to_alloc;
            OE_TEST(buf[index - 1].buf != NULL);
            max_size -= to_alloc;
            break;
        default:
            oe_abort();
    }

    *index_ = (int)index;
    *max_size_ = max_size;
}

static void _free_buffers(buffer* buf, int index)
{
    for (int i = 0; i < index; i++)
    {
        if (!buf[i].buf)
            continue;
        free(buf[i].buf);
        buf[i].buf = NULL;
        buf[i].size = 0;
    }
}

static void _run_malloc_test(size_t size)
{
    buffer array[ITERS];
    int index = 0;
    size_t original_size = size;

    // Make sure that the value can fit within a double since we use
    // double arithmetic below.
    OE_TEST(original_size == (size_t)(double)original_size);

    for (int i = 0; i < ITERS; i++)
    {
        /* Malloc if our array is empty. Otherwise, pick a random
         * fuction to execute. */
        int action = index == 0 ? TEST_MALLOC : (int)_randx(NUM_TESTS);

        switch (action)
        {
            case TEST_MALLOC:
            case TEST_CALLOC:
            case TEST_REALLOC:
                if (size < (size_t)((double)original_size * 0.15))
                {
                    /* Getting low on memory. Free all memory and do malloc. */
                    _free_buffers(array, index);
                    size = original_size;
                    index = 0;
                    _handle_alloc(array, TEST_MALLOC, &index, &size);
                }
                else
                {
                    _handle_alloc(array, action, &index, &size);
                }
                break;
            case TEST_FREE_0:
            case TEST_FREE_1:
                free(array[index - 1].buf);
                size += array[index - 1].size;
                array[index - 1].buf = NULL;
                array[index - 1].size = 0;
                index--;
                break;
            case TEST_SET_VAL:
                memset(array[index - 1].buf, 123, array[index - 1].size);
                break;
            case TEST_GET_VAL:
                OE_TEST(
                    memcmp(
                        array[index - 1].buf,
                        array[index - 1].buf,
                        array[index - 1].size) == 0);
                break;
            default:
                oe_abort();
        }
    }

    /* Clean up remaining buffers. */
    _free_buffers(array, index);
}

void init_malloc_stress_test()
{
    srand((unsigned int)time(NULL));
}

void malloc_stress_test(int threads)
{
    /* Get heap size. */
    size_t size = __oe_get_heap_size() - OE_USED_HEAP;

    /* Use the heap divided by the number of threads. */
    size = size / (size_t)threads;

    _run_malloc_test(size);
}
