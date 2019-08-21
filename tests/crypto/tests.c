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
    TestRdrand();
    TestHMAC();
    TestKDF();
    TestSHA();
}
