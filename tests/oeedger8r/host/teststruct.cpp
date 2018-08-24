// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include "../edltestutils.h"
#include "struct_u.c"

void test_struct_edl_ecalls(oe_enclave_t* enclave)
{
    const size_t count = 5;
    const size_t size = sizeof(MyStruct1) * 5;

    MyStruct1 retval = {0};
    MyStruct1 a1 = {{1}, 2};

    static MyStruct1 a2[5];
    for (size_t i = 0; i < 5; ++i)
        a2[i].s0.x = a2[i].y = i;

    static MyStruct1 a3[5][5];
    for (size_t i = 0; i < 5; ++i)
    {
        for (size_t j = 0; j < 5; ++j)
            a3[i][j].s0.x = a3[i][j].y = i * j;
    }

    MyStruct1 a4[1][1][1];
    a4[0][0][0] = MyStruct1{0};

    MyStruct1 a5 = {{5}, 5};
    MyStruct1 a6 = {{1}, 2};
    MyStruct1 a7 = {{0}, 0};

    static MyStruct1 a8[5];
    static MyStruct1 a9[5];
    static MyStruct1 a10[5];
    for (size_t i = 0; i < 5; ++i)
    {
        a8[i].s0.x = a8[i].y = 8;
        a9[i].s0.x = 1;
        a9[i].y = 2;
        a10[i].s0.x = a10[i].y = 0;
    }

    static MyStruct1 a11[5];
    static MyStruct1 a12[5];
    static MyStruct1 a13[5];
    for (size_t i = 0; i < 5; ++i)
    {
        a11[i].s0.x = a11[i].y = 11;
        a12[i].s0.x = 1;
        a12[i].y = 2;
        a13[i].s0.x = a13[i].y = 0;
    }

    static MyStruct1 a14[count];
    static MyStruct1 a15[count];
    static MyStruct1 a16[count];
    for (size_t i = 0; i < count; ++i)
    {
        a14[i].s0.x = a14[i].y = 14;
        a15[i].s0.x = 1;
        a15[i].y = 2;
        a16[i].s0.x = a16[i].y = 0;
    }

    static MyStruct1 a17[count];
    static MyStruct1 a18[count];
    static MyStruct1 a19[count];
    for (size_t i = 0; i < count; ++i)
    {
        a17[i].s0.x = a17[i].y = 17;
        a18[i].s0.x = 1;
        a18[i].y = 2;
        a19[i].s0.x = a19[i].y = 0;
    }

    OE_TEST(
        ecall_struct1(
            enclave,
            &retval,
            a1,
            a2,
            a3,
            a4,
            &a5,
            &a6,
            &a7,
            a8,
            a9,
            a10,
            a11,
            a12,
            a13,
            a14,
            a15,
            a16,
            a17,
            a18,
            a19,
            count,
            size) == OE_OK);

    OE_TEST(retval.s0.x == 1);
    OE_TEST(retval.y == 1);

    // a2 is in parameter and should not be modified.
    for (size_t i = 0; i < 5; ++i)
    {
        OE_TEST(a2[i].s0.x == (int)i);
        OE_TEST(a2[i].y == (int)i);
    }

    // a3 is in-out parameter that is expected to be set to 3.
    for (size_t i = 0; i < 5; ++i)
    {
        for (size_t j = 0; j < 5; ++j)
        {
            OE_TEST(a3[i][j].s0.x == 3);
            OE_TEST(a3[i][j].y == 3);
        }
    }

    // a4 is out parameter that is expected to be set to 4.
    OE_TEST(a4[0][0][0].s0.x == 4);
    OE_TEST(a4[0][0][0].y == 4);

    // a5 is 1 element in pointer. Must not be modified.
    OE_TEST(a5.s0.x == 5 && a5.y == 5);

    // a6 is 1 element in-out pointer that is expected to be set to 6.
    OE_TEST(a6.s0.x == 6 && a6.y == 6);

    // a7 is 1 element out pointer that is expected to be set to 7.
    OE_TEST(a7.s0.x == 7 && a7.y == 7);

    for (size_t i = 0; i < 5; ++i)
    {
        // a8 is 5 count in pointer that must not be modified.
        OE_TEST(a8[i].s0.x == 8 && a8[i].y == 8);

        // a9 is 5 count in-out pointer that is expected to be set to 9.
        OE_TEST(a9[i].s0.x == 9 && a9[i].y == 9);

        // a10 is 5 count out pointer that is expected to be set to 10.
        OE_TEST(a10[i].s0.x == 10 && a10[i].y == 10);
    }

    for (size_t i = 0; i < 5; ++i)
    {
        // a11 is 40 size in pointer that must not be modified.
        OE_TEST(a11[i].s0.x == 11 && a11[i].y == 11);

        // a12 is 40 size in-out pointer that is expected to be set to 12.
        OE_TEST(a12[i].s0.x == 12 && a12[i].y == 12);

        // a13 is 40 size out pointer that is expected to be set to 13.
        OE_TEST(a13[i].s0.x == 13 && a13[i].y == 13);
    }

    for (size_t i = 0; i < count; ++i)
    {
        // a14 is in pointer with attribute 'count' = count.
        // Must not be modified.
        OE_TEST(a14[i].s0.x == 14 && a14[i].y == 14);

        // a15 is in-out pointer with attribute 'count' = count.
        // Must be set to 15.
        OE_TEST(a15[i].s0.x == 15 && a15[i].y == 15);

        // a16 is out pointer with attribute 'count' = count.
        // Must be set to 16.
        OE_TEST(a16[i].s0.x == 16 && a16[i].y == 16);
    }

    for (size_t i = 0; i < count; ++i)
    {
        // a17 is in pointer with attribute 'size' = size.
        // Must not be modified.
        OE_TEST(a17[i].s0.x == 17 && a17[i].y == 17);

        // a18 is in-out pointer with attribute 'size' = size.
        // Must be set to 18.
        OE_TEST(a18[i].s0.x == 18 && a18[i].y == 18);

        // a19 is out pointer with attribute 'size' = size.
        // Must be set to 19.
        OE_TEST(a19[i].s0.x == 19 && a19[i].y == 19);
    }

    // Call with nulls.
    OE_TEST(
        ecall_struct1(
            enclave,
            &retval,
            a1,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            count,
            size) == OE_OK);

    OE_TEST(retval.s0.x == 2);
    OE_TEST(retval.y == 2);

    printf("=== test_struct_edl_ocalls passed\n");
}
