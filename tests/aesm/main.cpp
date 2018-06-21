// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>

//todo: remove this
#include <openenclave/internal/cpuid.h>
#include <openenclave/internal/tests.h>

#if defined(OE_USE_LIBSGX)
#include <sgx_ql_oe_wrapper.h>
#else
#include <openenclave/internal/aesm.h>
#endif

#define SKIP_RETURN_CODE 2

void asm_cpuid(unsigned int leaf, unsigned int subleaf, unsigned int* eax, unsigned int* ebx, unsigned int* ecx, unsigned int* edx)
{
    if (subleaf == NULL)
    {
        asm("cpuid\n\t"					
	       : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)	
	       : "0" (leaf));
    }

    asm("cpuid\n\t"					
	   : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)	
	   : "0" (leaf), "2" (subleaf));
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

    asm_cpuid(*leaf, *subleaf, &a_asm, &b_asm, &c_asm, &d_asm);

    OE_TEST(a == a_asm);
    OE_TEST(b == b_asm);
    OE_TEST(c == c_asm);
    OE_TEST(d == d_asm);
}

int main(int argc, const char* argv[])
{
    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf(
            "=== Skipped unsupported test in simulation mode "
            "(aesm)\n");
        return SKIP_RETURN_CODE;
    }

#if defined(OE_USE_LIBSGX)
    quote3_error_t err;
    sgx_target_info_t targetInfo = {};
    if (SGX_QL_SUCCESS != (err = sgx_qe_get_target_info(&targetInfo)))
    {
        printf("FAILED: Call returned %x\n", err);
        return -1;
    }
#else
    AESM* aesm;
    if (!(aesm = AESMConnect()))
    {
        fprintf(stderr, "%s: failed to connect\n", argv[0]);
        exit(1);
    }
#endif

    // TODO REMOVE
    unsigned int leaf = 0, subleaf = 0;
    TestCpuidAgainstAssembly(&leaf, &subleaf);

    // Since the subleaf is always required by our api, test out if 0 and not giving the field yield the same values.
    TestCpuidAgainstAssembly(&leaf, NULL);

    leaf = 0x80000000;
    TestCpuidAgainstAssembly(&leaf, &subleaf);

    leaf = 0x80000001;
    TestCpuidAgainstAssembly(&leaf, &subleaf);
    // REMOVE

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
