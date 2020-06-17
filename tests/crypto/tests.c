// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "tests.h"

void TestAll()
{
#if !defined(_WIN32)
    TestASN1();
#endif
    TestCRL();
    TestEC();
    TestRSA();
    TestRandom();
#if defined(__x86_64__) || defined(__i386__)
    // Test the RDRAND/RDSEED instructions, which are x86/64-specific.
    TestCpuEntropy();
#endif
    TestHMAC();
    TestKDF();
    TestSHA();
}
