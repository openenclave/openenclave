// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define MAX_LOOP_SIZE 1000

#include <openenclave/enclave.h>
#include <openenclave/internal/rdrand.h>
#include <openenclave/internal/rdseed.h>
#include <openenclave/internal/tests.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// Test that RDSEED and RDRAND functions synchronously block and
// retry until the sufficient entropy exists to be returned.
void TestCpuEntropy()
{
    uint64_t rand_num = 0;
    printf("=== begin %s()\n", __FUNCTION__);

    /* TODO: This test does not actually manage to exhaust the RDRAND
     * entropy pool regardless of the number of iterations run since
     * the operation of retrieving the RDRAND value through the bus
     * architecture is slow enough that a single thread can't saturate
     * the interface regardless of the number of iterations run.
     */
    for (uint64_t i = 0; i < MAX_LOOP_SIZE; i++)
    {
        rand_num = oe_rdrand();

        /* 0 is a legal random value that could be returned, but the
         * odds of this happening twice in a row are very unlikely
         * unless we've run out of hardware entropy and are returning
         * without retrying until we have sufficient entropy.
         */
        if (rand_num == 0)
        {
            rand_num = oe_rdrand();
            OE_TEST(rand_num != 0);
        }
    }

    /* Empirically, RDSEED will start to run out ~20 iterations, on a
     * Coffeelake device, so the MAX_LOOP_SIZE should be plenty.
     */
    for (uint64_t i = 0; i < MAX_LOOP_SIZE; i++)
    {
        rand_num = oe_rdseed();
        if (rand_num == 0)
        {
            rand_num = oe_rdseed();
            OE_TEST(rand_num != 0);
        }
    }

    printf("=== passed %s()\n", __FUNCTION__);
}
