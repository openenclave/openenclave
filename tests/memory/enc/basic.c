// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/tests.h>

#include <stdint.h>
#include <stdlib.h>

static void _SetBuffer(int* buf, size_t start, size_t end)
{
    for (size_t i = start; i < end; i++)
        buf[i] = i;
}

static void _CheckBuffer(int* buf, size_t start, size_t end)
{
    for (size_t i = start; i < end; i++)
        OE_TEST(buf[i] == i);
}

OE_ECALL void TestMalloc(void* args_)
{
    /* malloc(0) is implementation defined, but we can always free it. */
    int* ptr = (int*)malloc(0);
    free(ptr);

    /* Basic malloc test. */
    ptr = (int*)malloc(256 * sizeof(int));
    OE_TEST(ptr != NULL);
    _SetBuffer(ptr, 0, 256);
    _CheckBuffer(ptr, 0, 256);
    free(ptr);

    /* Ensure that malloc fails. */
    ptr = (int*)malloc(~((size_t)0));
    OE_TEST(ptr == NULL);
}

OE_ECALL void TestCalloc(void* args_)
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

OE_ECALL void TestRealloc(void* args_)
{
    /* Realloc with null pointer works like malloc. */
    int* ptr = (int*)realloc(NULL, 256 * sizeof(int));
    OE_TEST(ptr != NULL);
    _SetBuffer(ptr, 0, 256);
    _CheckBuffer(ptr, 0, 256);

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
    _CheckBuffer(ptr, 0, 256);
    _SetBuffer(ptr, 256, 1024);
    _CheckBuffer(ptr, 0, 1024);

    /* Realloc to contract pointer. */
    ptr = (int*)realloc(ptr, 16 * sizeof(int));
    OE_TEST(ptr != NULL);
    _CheckBuffer(ptr, 0, 16);

    /* Realloc to same size. */
    ptr = realloc(ptr, 16 * sizeof(int));
    OE_TEST(ptr != NULL);
    _CheckBuffer(ptr, 0, 16);

    /* Ensure that realloc fails. */
    void* ptr2 = realloc(ptr, ~((size_t)0));
    OE_TEST(ptr2 == NULL);

    /* realloc(X, 0) is implementation defined, but we can always free it. */
    free(ptr);
    ptr = realloc(NULL, 16 * sizeof(int));
    free(ptr);
}

OE_ECALL void TestMemalign(void* args_)
{
    /* Get an align pointer below malloc's alignment. */
    int* ptr = (int*)memalign(8, 256 * sizeof(int));
    OE_TEST(ptr != NULL);
    OE_TEST((uintptr_t)ptr % 8 == 0);
    _SetBuffer(ptr, 0, 256);
    _CheckBuffer(ptr, 0, 256);
    free(ptr);

    /* Get an aligned pointer beyond malloc's alignment. */
    ptr = (int*)memalign(64, 256 * sizeof(int));
    OE_TEST(ptr != NULL);
    OE_TEST((uintptr_t)ptr % 64 == 0);
    _SetBuffer(ptr, 0, 256);
    _CheckBuffer(ptr, 0, 256);
    free(ptr);

    /* Should fail if out of memory. */
    size_t max = ((size_t)1) << 63;
    OE_TEST(memalign(64, max) == NULL);

    /* Should fail if alignment isn't possible. */
    OE_TEST(memalign(max, 64) == NULL);
}

OE_ECALL void TestPosixMemalign(void* args_)
{
    void* ptr = NULL;

    /* Get an align pointer below malloc's alignment. */
    OE_TEST(posix_memalign(&ptr, 8, 256 * sizeof(int)) == 0);
    OE_TEST(ptr != NULL);
    OE_TEST((uintptr_t)ptr % 8 == 0);
    _SetBuffer((int*)ptr, 0, 256);
    _CheckBuffer((int*)ptr, 0, 256);
    free(ptr);

    /* Get an aligned pointer beyond malloc's alignment. */
    OE_TEST(posix_memalign(&ptr, 64, 256 * sizeof(int)) == 0);
    OE_TEST(ptr != NULL);
    OE_TEST((uintptr_t)ptr % 64 == 0);
    _SetBuffer((int*)ptr, 0, 256);
    _CheckBuffer((int*)ptr, 0, 256);
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
