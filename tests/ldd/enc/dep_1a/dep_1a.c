// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

__attribute__((weak)) int multiply_local_const_2a(int a);
__attribute__((weak)) int add_global_2a(int a, int b);

__attribute__((weak)) int unlinked_function(int a, int b);

int test_nested_dependencies()
{
    int failed_tests = 0;

    if (multiply_local_const_2a)
    {
        const int expected = 20010;
        int value = multiply_local_const_2a(10);
        if (value != expected)
            failed_tests++;
    }
    else
    {
        failed_tests++;
    }

    if (add_global_2a)
    {
        const int expected = 21111;
        int value = add_global_2a(1000, 100);
        if (value != expected)
            failed_tests++;
    }
    else
    {
        failed_tests++;
    }

    /*
     * Negative test for unbound functions
     */
    if (unlinked_function)
    {
        failed_tests++;
    }

    return failed_tests;
}
