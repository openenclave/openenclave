// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define MAX_LOOP_SIZE 100000000
#include <openenclave/enclave.h>
#include <openenclave/internal/rdrand.h>
#include <openenclave/internal/tests.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// TestRdrand is trying to ensure that oe_rdrand function incorporates blocking
// wait to retry if the RDRAND instruction is out of entropy
void TestRdrand()
{
    uint64_t rand_num = 0;
    printf("=== begin %s()\n", __FUNCTION__);
    for (uint64_t i = 0; i < MAX_LOOP_SIZE; i++)
    {
        rand_num = oe_rdrand();
        if (rand_num == 0)
        {
            rand_num = oe_rdrand();
            OE_TEST(rand_num != 0);
        }
    }
    printf("=== passed %s()\n", __FUNCTION__);
}
