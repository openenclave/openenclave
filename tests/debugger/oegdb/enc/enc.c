// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// The line numbers in this file are referenced by the gdb
// test script commands.gdb. If you edit this file, update the
// test script as well.
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "oe_gdb_test_t.h"

bool g_square_called = false;

int enc_add(int a, int b)
{
    // c is marked volatile to prevent compiler optimizations.
    // c is changed by the debugger.
    volatile int c = a + b;
    OE_TEST(c == 11);
    printf("hello: c = %d\n", c);

    // Expect debugger to change c to 100
    OE_TEST(c == 100);
    printf("hello: c = %d\n", c);

    // Expect debugger to call square and change c.
    OE_TEST(c == 10000);
    OE_TEST(g_square_called);
    printf("hello: c = %d\n", c);
    return c;
}

int square(int x)
{
    printf("square called with %d\n", x);
    printf(
        "x lies %s\n",
        oe_is_within_enclave(&x, sizeof(x)) ? "within enclave"
                                            : "outside enclave");
    g_square_called = true;
    return x * x;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
