// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>

#include "all_t.h"

void test_switchless_edl_ocalls()
{
    int c = 0;
    OE_TEST(ocall_sum(&c, 5, 6) == OE_OK);

    // Switchless calls are not yet implemented
    OE_TEST(switchless_ocall_sum(&c, 5, 6) == OE_OK);

    printf("=== test_switchless_edl_ocalls passed\n");
}

int ecall_sum(int a, int b)
{
    return a + b;
}

int switchless_ecall_sum(int a, int b)
{
    return a + b;
}
