// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/tests.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../args.h"

#define ITERS 1000

/* We have two free so that the number of frees is balanced with the ones
 * that allocate memory (malloc and calloc). */
#define TEST_MALLOC 0
#define TEST_CALLOC 1
#define TEST_REALLOC 2
#define TEST_FREE_0 3
#define TEST_FREE_1 4
#define TEST_SET_VAL 5
#define TEST_GET_VAL 6
#define NUM_TESTS 7

static inline size_t _RandX(size_t x)
{
    /* Note that rand() % N is biased if RAND_MAX + 1 isn't divisible
     * by N. But, slight probability bias doesn't really mater in these
     * tests. */
    return rand() % x;
}

static inline size_t _Min(size_t x, size_t y)
{
    return (x < y) ? x : y;
}

static size_t _GetAllocSize(size_t size)
{
    /*
     * Simple distribution to test varied memory allocation:
     *  - 20% of the time pick 0 <= x < 64 bytes.
     *  - 30% of the time pick 64 <= x <= 4K bytes.
     *  - 30% of the time pick 4K <= x <= 256K bytes.
     *  - 20% of the time pick 256K <= x < 16MB bytes.
     */
    size_t val = _RandX(100);
    if (val < 20)
        return _Min(_RandX(64), size);
    else if (val < 50)
        return _Min(_RandX(4096), size);
    else if (val < 80)
        return _Min(_RandX(256 * 1024), size);
    else
        return _Min(_RandX(16 * 1024 * 1024), size);
}

static void _HandleAlloc(
    Buffer* buffer,
    int action,
    int* index_,
    size_t* maxSize_)
{
    size_t index = *index_;
    size_t maxSize = *maxSize_;
    size_t toAlloc = _GetAllocSize(maxSize);

    switch (action)
    {
        /* For malloc/calloc, we add the new memory block to buffer array. */
        case TEST_MALLOC:
            buffer[index].buf = (unsigned char*)malloc(toAlloc);
            buffer[index].size = toAlloc;
            OE_TEST(buffer[index].buf != NULL);
            maxSize -= toAlloc;
            index++;
            break;
        case TEST_CALLOC:
            buffer[index].buf = (unsigned char*)calloc(1, toAlloc);
            buffer[index].size = toAlloc;
            OE_TEST(buffer[index].buf != NULL);
            maxSize -= toAlloc;
            index++;
            break;

        /* For realloc, we change the last allocated block. */
        case TEST_REALLOC:
            maxSize += buffer[index - 1].size;
            buffer[index - 1].buf =
                (unsigned char*)realloc(buffer[index - 1].buf, toAlloc);
            buffer[index - 1].size = toAlloc;
            OE_TEST(buffer[index - 1].buf != NULL);
            maxSize -= toAlloc;
            break;
        default:
            oe_abort();
    }

    *index_ = index;
    *maxSize_ = maxSize;
}

static void _FreeBuffers(Buffer* buffer, int index)
{
    for (int i = 0; i < index; i++)
    {
        free(buffer[i].buf);
        buffer[i].buf = NULL;
        buffer[i].size = 0;
    }
}

static void _RunMallocTest(size_t size)
{
    Buffer array[ITERS];
    int index = 0;
    size_t originalSize = size;

    for (int i = 0; i < ITERS; i++)
    {
        /* Malloc if our array is empty. Otherwise, pick a random
         * fuction to execute. */
        size_t action = index == 0 ? TEST_MALLOC : _RandX(NUM_TESTS);

        switch (action)
        {
            case TEST_MALLOC:
            case TEST_CALLOC:
            case TEST_REALLOC:
                if (size < originalSize * 0.15)
                {
                    /* Getting low on memory. Free all memory and do malloc. */
                    _FreeBuffers(array, index);
                    size = originalSize;
                    index = 0;
                    _HandleAlloc(array, TEST_MALLOC, &index, &size);
                }
                else
                {
                    _HandleAlloc(array, action, &index, &size);
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
    _FreeBuffers(array, index);
}

OE_ECALL void InitMallocStressTest(void* args)
{
    srand(time(NULL));
}

OE_ECALL void MallocStressTest(void* args_)
{
    /* Check host input. */
    MallocStressTestArgs* args = (MallocStressTestArgs*)args;
    OE_TEST(args != NULL);
    OE_TEST(oe_is_outside_enclave(args, sizeof(MallocStressTestArgs)));

    MallocStressTestArgs margs = *args;

    /* Get available heap. */
    const uint8_t* cur = (const uint8_t*)oe_sbrk(0);
    const uint8_t* end = (const uint8_t*)__oe_get_heap_end();
    OE_TEST(cur < end);
    size_t size = end - cur;

    /* Use the heap divided by the number of threads. */
    size = (size_t)size / margs.threads;

    _RunMallocTest(size);
}
