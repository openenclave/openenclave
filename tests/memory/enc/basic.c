// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/tests.h>

#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>

#include "memory_t.h"

static void _set_buffer(int* buf, size_t start, size_t end)
{
    for (size_t i = start; i < end; i++)
        buf[i] = (int)i;
}

static void _check_buffer(int* buf, size_t start, size_t end)
{
    for (size_t i = start; i < end; i++)
        OE_TEST(buf[i] == (int)i);
}

void test_malloc(void)
{
    /* malloc(0) is implementation defined, but we can always free it. */
    int* ptr = (int*)malloc(0);
    free(ptr);

    /* Basic malloc test. */
    ptr = (int*)malloc(256 * sizeof(int));
    OE_TEST(ptr != NULL);
    _set_buffer(ptr, 0, 256);
    _check_buffer(ptr, 0, 256);
    free(ptr);

    /* Ensure that malloc fails. */
    ptr = (int*)malloc(~((size_t)0));
    OE_TEST(ptr == NULL);
}

void test_calloc(void)
{
    /* calloc with 0 is implementation defined, but we can always free it. */
    int* ptr = (int*)calloc(0, 0);
    free(ptr);

    /* Basic calloc test. */
    ptr = (int*)calloc(256, sizeof(int));
    OE_TEST(ptr != NULL);
    for (int i = 0; i < 256; i++)
        OE_TEST(ptr[i] == 0);
    free(ptr);

    /* Ensure that calloc fails. */
    ptr = (int*)calloc(1, ~((size_t)0));
    OE_TEST(ptr == NULL);
}

void test_realloc(void)
{
    /* Realloc with null pointer works like malloc. */
    int* ptr = (int*)realloc(NULL, 256 * sizeof(int));
    OE_TEST(ptr != NULL);
    _set_buffer(ptr, 0, 256);
    _check_buffer(ptr, 0, 256);

    /*
     * Realloc to different pointer sizes. Although most implementations
     * like dlmalloc or glibc malloc try to reuse the realloc'd pointer if
     * possible, we can't test for it, since the C standard doesn't specify
     * reusing realloc'd pointers.
     */

    /* Realloc to expand pointer. Ensure that the values up to the original
     * size are not changed. */
    ptr = (int*)realloc(ptr, 1024 * sizeof(int));
    OE_TEST(ptr != NULL);
    _check_buffer(ptr, 0, 256);
    _set_buffer(ptr, 256, 1024);
    _check_buffer(ptr, 0, 1024);

    /* Realloc to contract pointer. */
    ptr = (int*)realloc(ptr, 16 * sizeof(int));
    OE_TEST(ptr != NULL);
    _check_buffer(ptr, 0, 16);

    /* Realloc to same size. */
    ptr = realloc(ptr, 16 * sizeof(int));
    OE_TEST(ptr != NULL);
    _check_buffer(ptr, 0, 16);

    /* Ensure that realloc fails. With GCC 7, this throws a
       compilation error, which we ignore. */
#if __GNUC__ >= 7
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Walloc-size-larger-than="
#endif
    void* ptr2 = realloc(ptr, ~((size_t)0));
#if __GNUC__ >= 7
#pragma GCC diagnostic pop
#endif
    OE_TEST(ptr2 == NULL);

    /* realloc(X, 0) is implementation defined, but we can always free it. */
    free(ptr);
    ptr = realloc(NULL, 0);
    free(ptr);
}

void test_memalign(void)
{
    /* Get an aligned pointer below malloc's alignment. */
    int* ptr = (int*)memalign(8, 256 * sizeof(int));
    OE_TEST(ptr != NULL);
    OE_TEST((uintptr_t)ptr % 8 == 0);
    _set_buffer(ptr, 0, 256);
    _check_buffer(ptr, 0, 256);
    free(ptr);

    /* Get an aligned pointer beyond malloc's alignment. */
    ptr = (int*)memalign(64, 256 * sizeof(int));
    OE_TEST(ptr != NULL);
    OE_TEST((uintptr_t)ptr % 64 == 0);
    _set_buffer(ptr, 0, 256);
    _check_buffer(ptr, 0, 256);
    free(ptr);

    /* Should fail if out of memory. */
    size_t max = ((size_t)1) << 63;
    OE_TEST(memalign(64, max) == NULL);

    /* Should fail if alignment isn't possible. */
    OE_TEST(memalign(max, 64) == NULL);
}

void test_posix_memalign(void)
{
    void* ptr = NULL;

    /* Get an align pointer below malloc's alignment. */
    OE_TEST(posix_memalign(&ptr, 8, 256 * sizeof(int)) == 0);
    OE_TEST(ptr != NULL);
    OE_TEST((uintptr_t)ptr % 8 == 0);
    _set_buffer((int*)ptr, 0, 256);
    _check_buffer((int*)ptr, 0, 256);
    free(ptr);

    /* Get an aligned pointer beyond malloc's alignment. */
    OE_TEST(posix_memalign(&ptr, 64, 256 * sizeof(int)) == 0);
    OE_TEST(ptr != NULL);
    OE_TEST((uintptr_t)ptr % 64 == 0);
    _set_buffer((int*)ptr, 0, 256);
    _check_buffer((int*)ptr, 0, 256);
    free(ptr);

    /* Should fail if alignment isn't a power of 2 or a multiple of
     * sizeof(void*). */
    OE_TEST(posix_memalign(&ptr, 0, 256 * sizeof(int)) != 0);
    OE_TEST(posix_memalign(&ptr, 2, 256 * sizeof(int)) != 0);
    OE_TEST(posix_memalign(&ptr, 63, 256 * sizeof(int)) != 0);

    /* Should fail if out of memory. */
    size_t max = ((size_t)1) << 63;
    OE_TEST(posix_memalign(&ptr, 64, max) != 0);

    /* Should fail if alignment isn't possible. */
    OE_TEST(posix_memalign(&ptr, max, 64) != 0);
}

void test_malloc_usable_size(void)
{
    int* p1 = (int*)malloc(sizeof *p1);
    OE_TEST(p1);
    int* p2 = (int*)malloc(sizeof *p2);
    OE_TEST(p2);

    /* Ensure that p1 < p2 so that we can use p2 as upper bound. */
    if (p1 > p2)
    {
        int* const tmp = p1;
        p1 = p2;
        p2 = tmp;
    }
    OE_TEST(p1 < p2);

    const size_t s1 = malloc_usable_size(p1);
    OE_TEST(sizeof *p1 <= s1 && s1 <= (size_t)(p2 - p1) * sizeof *p1);

    OE_TEST(sizeof *p2 <= malloc_usable_size(p2));

    const size_t end = s1 / sizeof *p1;
    _set_buffer(p1, 0, end);
    _check_buffer(p1, 0, end);
    free(p1);
    free(p2);
}
