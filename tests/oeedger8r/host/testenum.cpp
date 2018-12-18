// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <algorithm>
#include "all_u.h"

void test_enum_edl_ecalls(oe_enclave_t* enclave)
{
    // All inputs are initialized to Green.
    // All outputs are expected to be Blue.

    const size_t count = 5;
    const size_t size = 20;
    Color a1 = Red;
    Color ret_val = Blue;

    static Color a2[5];
    static Color a3[5][5];
    static Color a4[1][1][1];

    // in
    for (size_t i = 0; i < 5; ++i)
        a2[i] = Green;

    // in-out
    for (size_t i = 0; i < 5; ++i)
        for (size_t j = 0; j < 5; ++j)
            a3[i][j] = Green;

    // out. Value unused.
    a4[0][0][0] = Green;

    // 1 element arrays
    Color a5[1] = {Green};
    Color a6[1] = {Green};
    Color a7[1] = {Red};

    // 5 count arrays
    static Color a8[5];
    static Color a9[5];
    static Color a10[5];
    for (size_t i = 0; i < 5; ++i)
    {
        // in
        a8[i] = Green;
        // in-out
        a9[i] = Green;
        // out
        a10[i] = Red;
    }

    // size specified as 8 in EDL.
    const size_t count1 = 8 / sizeof(Color);
    static Color a11[count1];
    static Color a12[count1];
    static Color a13[count1];
    for (size_t i = 0; i < count1; ++i)
    {
        // in
        a11[i] = Green;
        // in-out
        a12[i] = Green;
        // out
        a13[i] = Red;
    }

    // count = count parameter.
    static Color a14[count];
    static Color a15[count];
    static Color a16[count];
    for (size_t i = 0; i < count; ++i)
    {
        // in
        a14[i] = Green;
        // in-out
        a15[i] = Green;
        // out
        a16[i] = Red;
    }

    // size = size parameter.
    const size_t count2 = size / sizeof(Color);
    static Color a17[count2];
    static Color a18[count2];
    static Color a19[count2];
    for (size_t i = 0; i < count2; ++i)
    {
        // in
        a17[i] = Green;
        // in-out
        a18[i] = Green;
        // out
        a19[i] = Red;
    }

    OE_TEST(
        ecall_enum1(
            enclave,
            &ret_val,
            a1,
            a2,
            a3,
            a4,
            a5,
            a6,
            a7,
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

    OE_TEST(ret_val == Red);

    {
        // in. Unchanged.
        for (size_t i = 0; i < 5; ++i)
            OE_TEST(a2[i] == Green);

        // in-out.
        for (size_t i = 0; i < 5; ++i)
            for (size_t j = 0; j < 5; ++j)
                OE_TEST(a3[i][j] == Blue);

        OE_TEST(a4[0][0][0] == Blue);
    }

    {
        // in. Unchanged.
        OE_TEST(a5[0] == Green);

        // in-out.
        OE_TEST(a6[0] == Blue);

        // out
        OE_TEST(a7[0] == Blue);
    }

    // count = 5
    for (size_t i = 0; i < 5; ++i)
    {
        // in. Unchanged.
        OE_TEST(a8[i] == Green);

        // in-out. Changed.
        OE_TEST(a9[i] == Blue);

        // out. Changed.
        OE_TEST(a10[i] == Blue);
    }

    // size = 8
    for (size_t i = 0; i < count1; ++i)
    {
        // in. Unchanged.
        OE_TEST(a11[i] == Green);

        // in-out. Changed.
        OE_TEST(a12[i] == Blue);

        // out. Changed.
        OE_TEST(a13[i] == Blue);
    }

    // count = count parameter
    for (size_t i = 0; i < count; ++i)
    {
        // in. Unchanged.
        OE_TEST(a14[i] == Green);

        // in-out. Changed.
        OE_TEST(a15[i] == Blue);

        // out. Changed.
        OE_TEST(a16[i] == Blue);
    }

    // size = size parameter
    for (size_t i = 0; i < count2; ++i)
    {
        // in. Unchanged.
        OE_TEST(a17[i] == Green);

        // in-out. Changed.
        OE_TEST(a18[i] == Blue);

        // out. Changed.
        OE_TEST(a19[i] == Blue);
    }

    OE_TEST(
        ecall_enum1(
            enclave,
            &ret_val,
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

    OE_TEST(ret_val == Green);

    printf("=== test_enum_edl_ecalls passed\n");
}

static int num = 0;

Color ocall_enum1(
    Color a1,
    Color a2[5],
    Color a3[5][5],
    Color a4[1][1][1],
    Color* a5,
    Color* a6,
    Color* a7,
    Color* a8,
    Color* a9,
    Color* a10,
    Color* a11,
    Color* a12,
    Color* a13,
    Color* a14,
    Color* a15,
    Color* a16,
    Color* a17,
    Color* a18,
    Color* a19,
    size_t count,
    size_t size)
{
    OE_TEST(a1 == Red);

    if (a2 && a3 && a4)
    {
        // in
        for (size_t i = 0; i < 5; ++i)
        {
            OE_TEST(a2[i] == Green);
            a2[i] = Blue;
        }

        // in-out
        for (size_t i = 0; i < 5; ++i)
        {
            for (size_t j = 0; j < 5; ++j)
            {
                OE_TEST(a3[i][j] == Green);
                a3[i][j] = Blue;
            }
        }

        // out
        a4[0][0][0] = Blue;
    }

    if (a5 && a6 && a7)
    {
        // in
        OE_TEST(a5[0] == Green);
        a5[0] = Blue;

        // in-out
        OE_TEST(a6[0] == Green);
        a6[0] = Blue;

        // out
        a7[0] = Blue;
    }

    if (a8 && a9 && a10)
    {
        for (size_t i = 0; i < 5; ++i)
        {
            // in
            OE_TEST(a8[i] == Green);
            // Should not affect host.
            a8[i] = Blue;

            // in-out.
            OE_TEST(a9[i] == Green);
            a9[i] = Blue;

            // out.
            a10[i] = Blue;
        }
    }

    if (a11 && a12 && a13)
    {
        // size declared as 8 in EDL.
        size_t count = 8 / sizeof(Color);
        for (size_t i = 0; i < count; ++i)
        {
            // in
            OE_TEST(a11[i] == Green);
            // Should not affect host.
            a11[i] = Blue;

            // in-out.
            OE_TEST(a12[i] == Green);
            a12[i] = Blue;

            // out.
            a13[i] = Blue;
        }
    }

    if (a14 && a15 && a16)
    {
        // count = count parameter
        for (size_t i = 0; i < count; ++i)
        {
            // in
            OE_TEST(a14[i] == Green);
            // Should not affect host.
            a14[i] = Blue;

            // in-out.
            OE_TEST(a15[i] == Green);
            a15[i] = Blue;

            // out.
            a16[i] = Blue;
        }
    }

    if (a17 && a18 && a19)
    {
        // size = size parameter.
        size_t count = size / sizeof(Color);
        for (size_t i = 0; i < count; ++i)
        {
            // in
            OE_TEST(a17[i] == Green);
            // Should not affect host.
            a17[i] = Blue;

            // in-out.
            OE_TEST(a18[i] == Green);
            a18[i] = Blue;

            // out.
            a19[i] = Blue;
        }
    }

    return (Color)++num;
}
