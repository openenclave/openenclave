// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>

#include "all_u.h"

void test_switchless_edl_ecalls(oe_enclave_t* enclave)
{
    int c = 0;
    OE_TEST(ecall_sum(enclave, &c, 5, 6) == OE_OK);

    // Switchless calls are not yet implemented
    OE_TEST(switchless_ecall_sum(enclave, &c, 5, 6) == OE_UNSUPPORTED);

    printf("=== test_switchless_edl_ecalls passed\n");
}

int ocall_sum(int a, int b)
{
    return a + b;
}

int switchless_ocall_sum(int a, int b)
{
    return a + b;
}
