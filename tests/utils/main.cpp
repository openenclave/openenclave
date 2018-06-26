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

void asm_cpuid(unsigned int leaf, unsigned int* subleaf, unsigned int* eax, unsigned int* ebx, unsigned int* ecx, unsigned int* edx)
{
    if (subleaf == NULL)
    {
        asm("cpuid\n\t"					
	       : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)	
	       : "0" (leaf));
    }

    asm("cpuid\n\t"					
	   : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)	
	   : "0" (leaf), "2" (*subleaf));
}

void TestCpuidAgainstAssembly(unsigned int* leaf, unsigned int* subleaf)
{
    unsigned int a_asm = 0, b_asm = 0, c_asm = 0, d_asm = 0;
    unsigned int a = 0, b = 0, c = 0, d = 0;

    if (subleaf == NULL)
    {
        oe_get_cpuid(*leaf, 0, &a, &b, &c, &d);
    }
    else
    {
        oe_get_cpuid(*leaf, *subleaf, &a, &b, &c, &d);
    }

    asm_cpuid(*leaf, subleaf, &a_asm, &b_asm, &c_asm, &d_asm);

    OE_TEST(a == a_asm);
    OE_TEST(b == b_asm);
    OE_TEST(c == c_asm);
    OE_TEST(d == d_asm);
}

int main()
{
    unsigned int leaf = 0, subleaf = 0;
    TestCpuidAgainstAssembly(&leaf, &subleaf);

    // Since the subleaf is always required by our api, test out if 0 and not giving the field yield the same values.
    TestCpuidAgainstAssembly(&leaf, NULL);

    leaf = 0x80000000;
    TestCpuidAgainstAssembly(&leaf, &subleaf);

    leaf = 0x80000001;
    TestCpuidAgainstAssembly(&leaf, &subleaf);

    return 0;
}