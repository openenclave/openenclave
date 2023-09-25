// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "tests.h"

void TestAll(char* path)
{
#if !defined(_WIN32)
    TestASN1(path);
#endif
    TestCRL(path);
#if defined(OE_BUILD_ENCLAVE)
    TestCert();
#endif
    TestEC(path);
    TestRSA(path);
    TestRandom();
#if defined(__x86_64__) || defined(__i386__)
    // Test the RDRAND/RDSEED instructions, which are x86/64-specific.
    TestCpuEntropy();
#endif
    TestHMAC();
    TestKDF();
    TestSHA();
}
