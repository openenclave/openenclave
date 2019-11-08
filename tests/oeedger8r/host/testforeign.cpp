// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <algorithm>
#include "all_u.h"

template <typename F>
static void test_ecall(oe_enclave_t* enclave, F f, size_t count)
{
    my_type1* a1 = new my_type1[count];
    my_type1* a2 = new my_type1[count];
    my_type1* a3 = new my_type1[count];

    for (size_t i = 0; i < count; ++i)
    {
        // in
        a1[i].x = 1;
        a1[i].y = 2;

        // in-out
        a2[i].x = 1;
        a2[i].y = 2;

        // out
        a3[i].x = 0;
        a3[i].y = 0;
    }

    OE_TEST(f(enclave, a1, a2, a3) == OE_OK);

    for (size_t i = 0; i < count; ++i)
    {
        // in. Unchanged.
        OE_TEST(a1[i].x == 1 && a1[i].y == 2);

        // in-out
        OE_TEST(a2[i].x == 2 && a2[i].y == 3);

        // out
        OE_TEST(a3[i].x == 2 && a3[i].y == 3);
    }

    // Call with nulls.
    OE_TEST(f(enclave, NULL, NULL, NULL) == OE_OK);

    delete[] a3;
    delete[] a2;
    delete[] a1;
}

void test_foreign_edl_ecalls(oe_enclave_t* enclave)
{
    // raw pointer to foreign type.
    test_ecall(enclave, ecall_foreign_ptr_1, 1);
    test_ecall(enclave, ecall_foreign_ptr_2, 5);
    test_ecall(enclave, ecall_foreign_ptr_3, 64 / sizeof(my_type1));

    test_ecall(
        enclave,
        [](oe_enclave_t* e, my_type1* a1, my_type1* a2, my_type1* a3) {
            return ecall_foreign_ptr_4(e, a1, a2, a3, 5);
        },
        5);

    test_ecall(
        enclave,
        [](oe_enclave_t* e, my_type1* a1, my_type1* a2, my_type1* a3) {
            return ecall_foreign_ptr_5(e, a1, a2, a3, 64);
        },
        64 / sizeof(my_type1));

    // foreign type (my_type2) that has isptr attribute.
    test_ecall(enclave, ecall_foreign_isptr_1, 1);
    test_ecall(enclave, ecall_foreign_isptr_2, 5);
    test_ecall(enclave, ecall_foreign_isptr_3, 64 / sizeof(my_type1));
    test_ecall(
        enclave,
        [](oe_enclave_t* e, my_type1* a1, my_type1* a2, my_type1* a3) {
            return ecall_foreign_isptr_4(e, a1, a2, a3, 5);
        },
        5);

    test_ecall(
        enclave,
        [](oe_enclave_t* e, my_type1* a1, my_type1* a2, my_type1* a3) {
            return ecall_foreign_isptr_5(e, a1, a2, a3, 64);
        },
        64 / sizeof(my_type1));

    // foreign type (my_type4) that has isary attribute.
    test_ecall(enclave, ecall_foreign_isary, 10);

    // call and return by value.
    my_type1 a1{1, 2};
    my_type1 ret_val{0, 0};
    OE_TEST(ecall_foreign_value(enclave, &ret_val, a1) == OE_OK);
    OE_TEST(a1.x == 1 && a1.y == 2);
    // y is expected to be number of successful ecalls.
    OE_TEST(ret_val.x == 2 && ret_val.y == 23);

    printf("=== test_foreign_edl_ecalls passed\n");
}

static int num = 0;

my_type1 ocall_foreign_value(my_type1 a1)
{
    OE_TEST(a1.x == 1 && a1.y == 2);
    return my_type1{a1.x + 1, ++num};
}

void test_args(my_type1* arg1, my_type1* arg2, my_type1* arg3, size_t count)
{
    if (arg1)
    {
        // in
        for (size_t i = 0; i < count; ++i)
        {
            OE_TEST(arg1[i].x == 1 && arg1[i].y == 2);
            // should not have any effect on host.
            arg1[i].x++;
            arg1[i].y++;
        }
    }

    if (arg2)
    {
        // in-out
        for (size_t i = 0; i < count; ++i)
        {
            OE_TEST(arg2[i].x == 1 && arg2[i].y == 2);
            arg2[i].x++;
            arg2[i].y++;
        }
    }

    if (arg3)
    {
        // out
        for (size_t i = 0; i < count; ++i)
        {
            arg3[i].x = 2;
            arg3[i].y = 3;
        }
    }
    ++num;
}

void ocall_foreign_ptr_1(my_type1* arg1, my_type1* arg2, my_type1* arg3)
{
    test_args(arg1, arg2, arg3, 1);
}

void ocall_foreign_ptr_2(my_type1* arg1, my_type1* arg2, my_type1* arg3)
{
    test_args(arg1, arg2, arg3, 5);
}

void ocall_foreign_ptr_3(my_type1* arg1, my_type1* arg2, my_type1* arg3)
{
    test_args(arg1, arg2, arg3, 64 / sizeof(my_type1));
}

void ocall_foreign_ptr_4(
    my_type1* arg1,
    my_type1* arg2,
    my_type1* arg3,
    size_t count)
{
    test_args(arg1, arg2, arg3, count);
}

void ocall_foreign_ptr_5(
    my_type1* arg1,
    my_type1* arg2,
    my_type1* arg3,
    size_t size)
{
    test_args(arg1, arg2, arg3, size / sizeof(my_type1));
}

void ocall_foreign_isptr_1(my_type2 arg1, my_type2 arg2, my_type2 arg3)
{
    test_args(arg1, arg2, arg3, 1);
}

void ocall_foreign_isptr_2(my_type2 arg1, my_type2 arg2, my_type2 arg3)
{
    test_args(arg1, arg2, arg3, 5);
}

void ocall_foreign_isptr_3(my_type2 arg1, my_type2 arg2, my_type2 arg3)
{
    test_args(arg1, arg2, arg3, 64 / sizeof(my_type1));
}

void ocall_foreign_isptr_4(
    my_type2 arg1,
    my_type2 arg2,
    my_type2 arg3,
    size_t count)
{
    test_args(arg1, arg2, arg3, count);
}

void ocall_foreign_isptr_5(
    my_type2 arg1,
    my_type2 arg2,
    my_type2 arg3,
    size_t size)
{
    test_args(arg1, arg2, arg3, size / sizeof(my_type1));
}

void ocall_foreign_isary(my_type3 arg1, my_type3 arg2, my_type3 arg3)
{
    test_args(arg1, arg2, arg3, 10);
}
