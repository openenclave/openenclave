// Copyright (c) Microsoft Corporation. All rights reserved.
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
    // This test exercises the rdrand instruction, which is x86/64-specific.
    TestRdrand();
#endif
    TestHMAC();
    TestKDF();
    TestSHA();
}
