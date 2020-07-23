// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>
#include "ldd_t.h"

__attribute__((weak)) int multiply_local_const_1a(int a);
__attribute__((weak)) int add_global_1a(int a, int b);

__attribute__((weak)) int multiply_local_const_1b(int a);
__attribute__((weak)) int add_global_1b(int a, int b);

__attribute__((weak)) int undefined_function(int a, int b);

int test_enclave()
{
    int failed_tests = 0;

    if (multiply_local_const_1a)
    {
        const int expected = 10010;
        int value = multiply_local_const_1a(10);
        printf(
            "multiply_local_const_1a(10) = %d, expected = %d\n",
            value,
            expected);
        if (value != expected)
            failed_tests++;
    }
    else
    {
        printf("multiply_local_const_1a not defined\n");
        failed_tests++;
    }

    if (add_global_1a)
    {
        const int expected = 11110;
        int value = add_global_1a(1000, 100);
        printf("add_global_1a(10) = %d, expected = %d\n", value, expected);
        if (value != expected)
            failed_tests++;
    }
    else
    {
        printf("add_global_1a not defined\n");
        failed_tests++;
    }

    if (multiply_local_const_1b)
    {
        const int expected = 10020;
        int value = multiply_local_const_1b(10);
        printf(
            "multiply_local_const_1b(10) = %d, expected = %d\n",
            value,
            expected);
        if (value != expected)
            failed_tests++;
    }
    else
    {
        printf("multiply_local_const_1b not defined\n");
        failed_tests++;
    }

    if (add_global_1b)
    {
        const int expected = 11120;
        int value = add_global_1b(1000, 100);
        printf("add_global_1b(10) = %d, expected = %d\n", value, expected);
        if (value != expected)
            failed_tests++;
    }
    else
    {
        printf("add_global_1b not defined\n");
        failed_tests++;
    }

    if (undefined_function)
    {
        printf("Found unexpected undefined_function\n");
        failed_tests++;
    }
    else
        printf("undefined_function is correctly not found\n");

    return failed_tests;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
