// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "sbrk_t.h"

void test_sbrk(void)
{
    const ptrdiff_t COUNT = 4;
    ptrdiff_t n = 0;
    ptrdiff_t m = 0;
    void* start;
    void* end;
    void* current;

    /* Remember the starting break value. */
    OE_TEST((start = (uint8_t*)oe_sbrk(0)));
    current = start;

    /* Allocate several times. */
    for (ptrdiff_t i = 0; i < COUNT; i++)
    {
        uint8_t* p = (uint8_t*)oe_sbrk(i);
        OE_TEST(p == current);
        current = (uint8_t*)p + i;
        n += i;
    }

    /* Check the ending break value. */
    end = oe_sbrk(0);
    OE_TEST(end != NULL);
    OE_TEST(end == (uint8_t*)start + n);

    /* Deallocate several times. */
    for (ptrdiff_t i = 0; i < COUNT; i++)
    {
        uint8_t* p = (uint8_t*)oe_sbrk(-i);
        OE_TEST(p != (void*)-1);
        m += i;
    }

    OE_TEST(m == n);

    /* The break value should be back where it started. */
    OE_TEST(oe_sbrk(0) == start);
    OE_TEST(((uint8_t*)end - m) == start);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
