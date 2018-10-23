// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "tests.h"

void TestAll()
{
    TestASN1();
    TestCRL();
    TestEC();
    TestRandom();
    TestRdrand();
    TestRSA();
    TestSHA();
}
