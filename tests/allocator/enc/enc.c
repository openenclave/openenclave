// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../allocator/allocator.h"

int test_allocator(void)
{
    const size_t N = 1024;
    void* pointers[N];

    /* Verify oe_allocator_startup() was called on this thread. */
    {
        bool found = false;

        for (size_t i = 0; i < allocator.num_threads; i++)
        {
            if (allocator.threads[i].id == oe_thread_self())
            {
                OE_TEST(allocator.threads[i].count == 1);
                found = true;
                break;
            }
        }

        OE_TEST(found = true);
    }

    /* Clear counters. */
    memset(&allocator, 0, sizeof(allocator));

    for (size_t i = 0; i < N; i++)
    {
        pointers[i] = malloc(i + 512);
        OE_TEST(pointers[i] != NULL);
    }

    for (size_t i = 0; i < N; i++)
    {
        free(pointers[i]);
    }

    OE_TEST(allocator.malloc_count == N);
    OE_TEST(allocator.free_count == N);

    oe_malloc_stats_t stats;
    OE_TEST(oe_allocator_get_stats(&stats) == OE_OK);
    OE_TEST(stats.peak_system_bytes == PEAK_SYSTEM_BYTES);
    OE_TEST(stats.system_bytes == SYSTEM_BYTES);
    OE_TEST(stats.in_use_bytes == IN_USE_BYTES);

    return 12345;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
