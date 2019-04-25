// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/array.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include "array_t.h"

void test_array(void)
{
    int r;
    oe_array_t a;
    const size_t N = 1024;

    r = oe_array_initialize(&a, sizeof(uint64_t), 16);
    OE_TEST(r == 0);

    for (uint64_t i = 0; i < N; i++)
    {
        r = oe_array_append(&a, &i);
        OE_TEST(r == 0);
        OE_TEST(a.size == i + 1);

        void* ptr = oe_array_get(&a, i);
        OE_TEST(ptr != NULL);
        OE_TEST(memcmp(ptr, &i, sizeof(i)) == 0);
    }

    OE_TEST(a.size == N);
    OE_TEST(a.capacity >= N);

    for (uint64_t i = 0; i < N; i++)
    {
        void* ptr = oe_array_get(&a, i);
        OE_TEST(ptr != NULL);
        OE_TEST(memcmp(ptr, &i, sizeof(i)) == 0);
    }

    oe_array_free(&a);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
