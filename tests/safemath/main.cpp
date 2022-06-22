// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/result.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/tests.h>

bool _check_8_bit_unsigned(oe_result_t result, int num, uint8_t num_u8)
{
    if ((num < 0 || num > OE_UINT8_MAX) && result != OE_INTEGER_OVERFLOW)
        return false;
    if ((num >= 0 && num <= OE_UINT8_MAX) && result != OE_OK)
        return false;
    if (result == OE_OK && num != num_u8)
        return false;
    return true;
}

bool _check_8_bit_signed(oe_result_t result, int num, int8_t num_s8)
{
    if ((num < OE_INT8_MIN || num > OE_INT8_MAX) &&
        result != OE_INTEGER_OVERFLOW)
        return false;
    if ((num >= OE_INT8_MIN && num <= OE_INT8_MAX) && result != OE_OK)
        return false;
    if (result == OE_OK && num != num_s8)
        return false;
    return true;
}

void _test_8_bit()
{
    /* Unsigned tests. */
    for (int a = 0; a <= OE_UINT8_MAX; a++)
    {
        for (int b = 0; b <= OE_UINT8_MAX; b++)
        {
            /* Test addition. */
            uint8_t c_u8;
            int c = a + b;
            oe_result_t res = oe_safe_add_u8((uint8_t)a, (uint8_t)b, &c_u8);
            if (!_check_8_bit_unsigned(res, c, c_u8))
                oe_put_err("oe_safe_add_u8() failed with inputs: %d %d", a, b);

            /* Test subtraction. */
            c = a - b;
            res = oe_safe_sub_u8((uint8_t)a, (uint8_t)b, &c_u8);
            if (!_check_8_bit_unsigned(res, c, c_u8))
                oe_put_err("oe_safe_sub_u8() failed with inputs: %d %d", a, b);

            /* Test multiplication. */
            c = a * b;
            res = oe_safe_mul_u8((uint8_t)a, (uint8_t)b, &c_u8);
            if (!_check_8_bit_unsigned(res, c, c_u8))
                oe_put_err("oe_safe_mul_u8() failed with inputs: %d %d", a, b);
        }
    }

    /* Signed tests. */
    for (int a = OE_INT8_MIN; a <= OE_INT8_MAX; a++)
    {
        for (int b = OE_INT8_MIN; b <= OE_INT8_MAX; b++)
        {
            /* Test addition. */
            int8_t c_s8;
            int c = a + b;
            oe_result_t res = oe_safe_add_s8((int8_t)a, (int8_t)b, &c_s8);
            if (!_check_8_bit_signed(res, c, c_s8))
                oe_put_err("oe_safe_add_s8() failed with inputs: %d %d", a, b);

            /* Test subtraction. */
            c = a - b;
            res = oe_safe_sub_s8((int8_t)a, (int8_t)b, &c_s8);
            if (!_check_8_bit_signed(res, c, c_s8))
                oe_put_err("oe_safe_sub_s8() failed with inputs: %d %d", a, b);

            /* Test multiplication. */
            c = a * b;
            res = oe_safe_mul_s8((int8_t)a, (int8_t)b, &c_s8);
            if (!_check_8_bit_signed(res, c, c_s8))
                oe_put_err("oe_safe_mul_s8() failed with inputs: %d %d", a, b);
        }
    }
}

template <typename T>
struct UnsignedTest
{
    oe_result_t (*add)(T, T, T*);
    oe_result_t (*sub)(T, T, T*);
    oe_result_t (*mul)(T, T, T*);
    T limit;

    void Run()
    {
        TestAdd();
        TestSub();
        TestMul();
    }

    void TestAdd()
    {
        /* Check zeros. */
        T a = 0;
        T b = 0;
        T c;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == 0);

        a = limit;
        b = 0;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == limit);

        a = 0;
        b = limit;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == limit);

        /* Check limits. */
        a = limit;
        b = limit;
        OE_TEST(add(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* Check overflow occurs past limit. */
        a = limit;
        b = 1;
        OE_TEST(add(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = 1;
        b = limit;
        OE_TEST(add(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = limit / 2;
        b = limit;
        OE_TEST(add(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* Check overflow doesn't occur <= limit. */
        a = static_cast<T>(limit - 1);
        b = 1;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == limit);

        a = 1;
        b = static_cast<T>(limit - 1);
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == limit);

        a = limit / 2;
        b = limit / 2;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == limit - 1);

        /* Check basic math. */
        a = 15;
        b = 100;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == 115);

        a = 100;
        b = 15;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == 115);
    }

    void TestSub()
    {
        /* Check zeros. */
        T a = 0;
        T b = 0;
        T c;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == 0);

        a = limit;
        b = 0;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == limit);

        a = 0;
        b = limit;
        OE_TEST(sub(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* Check limit. */
        a = limit;
        b = limit;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == 0);

        /* Check overflow occurs when b > a. */
        a = 1;
        b = limit;
        OE_TEST(sub(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = limit / 2;
        b = limit;
        OE_TEST(sub(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = static_cast<T>(limit - 1);
        b = limit;
        OE_TEST(sub(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* Check overflow doesn't occur when a <= b. */
        a = limit;
        b = 1;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == limit - 1);

        a = limit;
        b = limit / 2;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == limit / 2 + 1);

        a = limit;
        b = static_cast<T>(limit - 1);
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == 1);

        a = 50;
        b = 50;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == 0);

        /* Check basic math. */
        a = 15;
        b = 100;
        OE_TEST(sub(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = 100;
        b = 15;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == 85);
    }

    void TestMul()
    {
        /* Check zeros. */
        T a = 0;
        T b = 0;
        T c;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == 0);

        a = limit;
        b = 0;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == 0);

        a = 0;
        b = limit;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == 0);

        /* Check ones. */
        a = 1;
        b = 1;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == 1);

        a = limit;
        b = 1;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == limit);

        a = 1;
        b = limit;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == limit);

        /* Check limits. */
        a = limit;
        b = limit;
        OE_TEST(mul(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* Check if overflow occurs past limit. */
        a = static_cast<T>(limit / 2 + 1);
        b = 2;
        OE_TEST(mul(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = limit / 2;
        b = 4;
        OE_TEST(mul(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* Check if overflow doesn't occur <= limit. */
        a = limit / 2;
        b = 2;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == limit - 1);

        /* Check basic math. */
        a = 15;
        b = 100;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == 1500);

        a = 100;
        b = 15;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == 1500);
    }
};

template <typename T>
struct SignedTest
{
    oe_result_t (*add)(T, T, T*);
    oe_result_t (*sub)(T, T, T*);
    oe_result_t (*mul)(T, T, T*);
    T min_limit;
    T max_limit;

    void Run()
    {
        TestAdd();
        TestSub();
        TestMul();
    }

    void TestAdd()
    {
        /* Test zeros. */
        T a = 0;
        T b = 0;
        T c;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == 0);

        a = max_limit;
        b = 0;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == max_limit);

        a = min_limit;
        b = 0;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == min_limit);

        a = 0;
        b = max_limit;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == max_limit);

        a = 0;
        b = min_limit;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == min_limit);

        /* Test limits. */
        a = max_limit;
        b = max_limit;
        OE_TEST(add(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = max_limit;
        b = min_limit;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == -1);

        a = min_limit;
        b = max_limit;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == -1);

        a = min_limit;
        b = min_limit;
        OE_TEST(add(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* Check overflow past limits. */
        a = max_limit;
        b = 1;
        OE_TEST(add(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = 1;
        b = max_limit;
        OE_TEST(add(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = min_limit;
        b = -1;
        OE_TEST(add(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = -1;
        b = min_limit;
        OE_TEST(add(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = max_limit;
        b = 10;
        OE_TEST(add(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = min_limit;
        b = -10;
        OE_TEST(add(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* Check if overflow doesn't occur at or before limits. */
        a = static_cast<T>(max_limit - 1);
        b = 1;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == max_limit);

        a = max_limit;
        b = -1;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == max_limit - 1);

        a = static_cast<T>(min_limit + 1);
        b = -1;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == min_limit);

        a = min_limit;
        b = 1;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == min_limit + 1);

        /* Check for two's complement behavior. */
        a = max_limit / 2;
        b = max_limit / 2;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == max_limit - 1);

        a = min_limit / 2;
        b = min_limit / 2;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == min_limit);

        /* Check basic math. */
        a = 15;
        b = 100;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == 115);

        a = 100;
        b = 15;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == 115);

        a = -15;
        b = 100;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == 85);

        a = 100;
        b = -15;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == 85);

        a = 15;
        b = -100;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == -85);

        a = -100;
        b = 15;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == -85);

        a = -15;
        b = -100;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == -115);

        a = -100;
        b = -15;
        OE_TEST(add(a, b, &c) == OE_OK);
        OE_TEST(c == -115);
    }

    void TestSub()
    {
        /* Test zeros. */
        T a = 0;
        T b = 0;
        T c;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == 0);

        a = max_limit;
        b = 0;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == max_limit);

        a = min_limit;
        b = 0;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == min_limit);

        a = 0;
        b = max_limit;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == -max_limit);

        a = 0;
        b = min_limit;
        OE_TEST(sub(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* Test limits. */
        a = max_limit;
        b = max_limit;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == 0);

        a = max_limit;
        b = min_limit;
        OE_TEST(sub(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = min_limit;
        b = max_limit;
        OE_TEST(sub(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = min_limit;
        b = min_limit;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == 0);

        a = min_limit;
        b = static_cast<T>(-max_limit);
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == -1);

        /* Check overflow happens past the limits. */
        a = max_limit;
        b = -1;
        OE_TEST(sub(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = min_limit;
        b = 1;
        OE_TEST(sub(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* Check overflow doesn't occur at <= limits. */
        a = static_cast<T>(max_limit - 1);
        b = -1;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == max_limit);

        a = max_limit;
        b = 1;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == max_limit - 1);

        a = static_cast<T>(min_limit + 1);
        b = 1;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == min_limit);

        a = min_limit;
        b = -1;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == min_limit + 1);

        /* Checks related to two's complement. */
        a = -1;
        b = max_limit;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == min_limit);

        a = -2;
        b = max_limit;
        OE_TEST(sub(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = -1;
        b = min_limit;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == max_limit);

        /* Check overflow when b > 0. */
        a = min_limit / 2;
        b = max_limit;
        OE_TEST(sub(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* Check overflow when b < 0. */
        a = max_limit / 2;
        b = min_limit;
        OE_TEST(sub(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* Check basic math. */
        a = 15;
        b = 100;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == -85);

        a = -15;
        b = 100;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == -115);

        a = 15;
        b = -100;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == 115);

        a = -15;
        b = -100;
        OE_TEST(sub(a, b, &c) == OE_OK);
        OE_TEST(c == 85);
    }

    void TestMul()
    {
        /* Test zeros. */
        T a = 0;
        T b = 0;
        T c;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == 0);

        a = max_limit;
        b = 0;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == 0);

        a = min_limit;
        b = 0;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == 0);

        a = 0;
        b = max_limit;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == 0);

        a = min_limit;
        b = 0;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == 0);

        /* Test ones. */
        a = 1;
        b = 1;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == 1);

        a = max_limit;
        b = 1;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == max_limit);

        a = 1;
        b = max_limit;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == max_limit);

        a = min_limit;
        b = 1;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == min_limit);

        a = 1;
        b = min_limit;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == min_limit);

        /* Test negative one. */
        a = -1;
        b = -1;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == 1);

        a = max_limit;
        b = -1;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == -max_limit);

        a = -1;
        b = max_limit;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == -max_limit);

        a = min_limit;
        b = -1;
        OE_TEST(mul(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = -1;
        b = min_limit;
        OE_TEST(mul(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* Test limits. */
        a = max_limit;
        b = max_limit;
        OE_TEST(mul(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = max_limit;
        b = min_limit;
        OE_TEST(mul(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = min_limit;
        b = max_limit;
        OE_TEST(mul(a, b, &c) == OE_INTEGER_OVERFLOW);

        a = min_limit;
        b = min_limit;
        OE_TEST(mul(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* When both are positive, check if overflow happens past limit. */
        a = max_limit / 2;
        b = 2;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == max_limit - 1);

        a = static_cast<T>(max_limit / 2 + 1);
        b = 2;
        OE_TEST(mul(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* When b is negative, check if overflow happens past limit. */
        a = static_cast<T>(max_limit / 2 + 1);
        b = -2;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == min_limit);

        a = static_cast<T>(max_limit / 2 + 2);
        b = -2;
        OE_TEST(mul(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* When a is negative, check if overflow happens past limit. */
        a = -2;
        b = static_cast<T>(max_limit / 2 + 1);
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == min_limit);

        a = -2;
        b = static_cast<T>(max_limit / 2 + 2);
        OE_TEST(mul(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* When both are negative, check if overflow happens past limit. */
        a = static_cast<T>(min_limit / 2 + 1);
        b = -2;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == max_limit - 1);

        a = min_limit / 2;
        b = -2;
        OE_TEST(mul(a, b, &c) == OE_INTEGER_OVERFLOW);

        /* Test basic math. */
        a = 15;
        b = 100;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == 1500);

        a = 100;
        b = 15;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == 1500);

        a = -15;
        b = 100;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == -1500);

        a = 100;
        b = -15;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == -1500);

        a = 15;
        b = -100;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == -1500);

        a = -100;
        b = 15;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == -1500);

        a = -15;
        b = -100;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == 1500);

        a = -100;
        b = -15;
        OE_TEST(mul(a, b, &c) == OE_OK);
        OE_TEST(c == 1500);
    }
};

void _test_unsigned()
{
    UnsignedTest<uint16_t> u16 = {
        oe_safe_add_u16, oe_safe_sub_u16, oe_safe_mul_u16, OE_UINT16_MAX};

    UnsignedTest<uint32_t> u32 = {
        oe_safe_add_u32, oe_safe_sub_u32, oe_safe_mul_u32, OE_UINT32_MAX};

    UnsignedTest<uint64_t> u64 = {
        oe_safe_add_u64, oe_safe_sub_u64, oe_safe_mul_u64, OE_UINT64_MAX};

    UnsignedTest<size_t> sizet = {
        oe_safe_add_sizet, oe_safe_sub_sizet, oe_safe_mul_sizet, OE_SIZE_MAX};

    u16.Run();
    u32.Run();
    u64.Run();
    sizet.Run();
}

void _test_signed()
{
    SignedTest<int16_t> s16 = {
        oe_safe_add_s16,
        oe_safe_sub_s16,
        oe_safe_mul_s16,
        OE_INT16_MIN,
        OE_INT16_MAX};

    SignedTest<int32_t> s32 = {
        oe_safe_add_s32,
        oe_safe_sub_s32,
        oe_safe_mul_s32,
        OE_INT32_MIN,
        OE_INT32_MAX};

    SignedTest<int64_t> s64 = {
        oe_safe_add_s64,
        oe_safe_sub_s64,
        oe_safe_mul_s64,
        OE_INT64_MIN,
        OE_INT64_MAX};

    s16.Run();
    s32.Run();
    s64.Run();
}

int main()
{
    /* For 8-bit math, we can quickly exhaust all combinations. */
    _test_8_bit();

    /* For the other sizes, we will test selected cases. */
    _test_unsigned();
    _test_signed();

    printf("=== passed all tests (safemath)\n");

    return 0;
}
