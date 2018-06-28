// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//
// This file contains tests for various utility functions in openenclave
//

#include <openenclave/bits/result.h>
#include <openenclave/internal/tests.h>

OE_EXTERNC oe_result_t oe_get_cpuid(
    unsigned int __leaf,
    unsigned int __subleaf,
    unsigned int* __eax,
    unsigned int* __ebx,
    unsigned int* __ecx,
    unsigned int* __edx);

void asm_get_cpuid(
    unsigned int leaf,
    unsigned int* subleaf,
    unsigned int* eax,
    unsigned int* ebx,
    unsigned int* ecx,
    unsigned int* edx)
{
#if defined(__GNUC__)
    if (subleaf == NULL)
    {
        asm volatile(
            "cpuid\n\t"
            : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
            : "0"(leaf)
            : "cc", "memory");
    }

    else
    {
        asm volatile(
            "cpuid\n\t"
            : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
            : "0"(leaf), "2"(*subleaf)
            : "cc", "memory");
    }
#endif
}

void TestCpuidAgainstAssembly(unsigned int leaf, unsigned int* subleaf)
{
    unsigned int a_asm = 0, b_asm = 0, c_asm = 0, d_asm = 0;
    unsigned int a = 0, b = 0, c = 0, d = 0;

    if (subleaf == NULL)
    {
        oe_get_cpuid(leaf, 0, &a, &b, &c, &d);
    }
    else
    {
        oe_get_cpuid(leaf, *subleaf, &a, &b, &c, &d);
    }

    asm_get_cpuid(leaf, subleaf, &a_asm, &b_asm, &c_asm, &d_asm);

    if (a_asm == 0)
    {
        fprintf(stdout, "a_asm is EQUAL TO 0");
    }

    OE_TEST(a == a_asm);
    OE_TEST(b == b_asm);
    OE_TEST(c == c_asm);
    OE_TEST(d == d_asm);
}

void TestUnequalLeaves()
{
    // Verify: different leaf values return different answers.
    unsigned int a_asm = 0, b_asm = 0, c_asm = 0, d_asm = 0;
    unsigned int a = 0, b = 0, c = 0, d = 0;

    oe_get_cpuid(0, 0, &a, &b, &c, &d);
    asm_get_cpuid(1, 0, &a_asm, &b_asm, &c_asm, &d_asm);

    OE_TEST(a != a_asm);

    // Verify: same oe and asm agree on those values.
    unsigned int a_asm_2 = 0, b_asm_2 = 0, c_asm_2 = 0, d_asm_2 = 0;
    unsigned int a_2 = 0, b_2 = 0, c_2 = 0, d_2 = 0;

    oe_get_cpuid(1, 0, &a_2, &b_2, &c_2, &d_2);
    asm_get_cpuid(0, 0, &a_asm_2, &b_asm_2, &c_asm_2, &d_asm_2);

    OE_TEST(a == a_asm_2);
    OE_TEST(a_2 == a_asm);
}

int main()
{
    unsigned int leaf = 0, subleaf = 0;

    fprintf(
        stdout,
        "Test: assembly call and function call give the same result.\n");
    TestCpuidAgainstAssembly(leaf, &subleaf);

    // Since the subleaf is always required by our api, test out if 0 and not
    // giving the field yield the same values.
    fprintf(
        stdout,
        "Test: result when subleaf is not provided to assembly call.\n");
    TestCpuidAgainstAssembly(leaf, NULL);
    TestCpuidAgainstAssembly(1, NULL);
    TestCpuidAgainstAssembly(2, NULL);

    leaf = 0x80000000;
    fprintf(stdout, "Test: Highest leaf.\n");
    TestCpuidAgainstAssembly(leaf, &subleaf);

    leaf = 0x80000001;
    fprintf(stdout, "Test: Out of bounds leaf.\n");
    TestCpuidAgainstAssembly(leaf, &subleaf);

    TestUnequalLeaves();

    return 0;
}
