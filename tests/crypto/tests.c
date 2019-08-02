// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "tests.h"

void TestAll()
{
#if !defined(_WIN32)
    TestASN1();
    TestCRL();
    TestEC();
    TestRSA();
#endif
    TestRandom();
#if defined(__x86_64__) || defined(__i386__)
    TestRdrand();
#endif
    TestHMAC();
    TestKDF();
    TestSHA();
}
