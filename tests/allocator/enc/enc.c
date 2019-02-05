// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../libmalloc/libmalloc.h"

void test_malloc(void)
{
    const size_t N = 1024;
    void* pointers[N];

    /* Verify oe_internal_malloc_thread_startup() was called on this thread. */
    {
        bool found = false;

        for (size_t i = 0; i < libmalloc.num_threads; i++)
        {
            if (libmalloc.threads[i].id == oe_thread_self())
            {
                OE_TEST(libmalloc.threads[i].count == 1);
                found = true;
                break;
            }
        }

        OE_TEST(found = true);
    }

    /* Clear counters. */
    memset(&libmalloc, 0, sizeof(libmalloc));

    for (size_t i = 0; i < N; i++)
    {
        pointers[i] = malloc(i + 512);
        OE_TEST(pointers[i] != NULL);
    }

    for (size_t i = 0; i < N; i++)
    {
        free(pointers[i]);
    }

    OE_TEST(libmalloc.malloc_count == N);
    OE_TEST(libmalloc.free_count == N);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
