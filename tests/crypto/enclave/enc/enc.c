// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/random.h>
#include <openenclave/internal/rsa.h>
#include <openenclave/internal/sha.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../ec_tests.h"
#include "../../hash.h"
#include "../../random_tests.h"
#include "../../rsa_tests.h"
#include "../../sha_tests.h"

OE_ECALL void Test(void* args_)
{
    oe_malloc_stats_t stats;

    /* Save the current malloc'd bytes in use */
    uint64_t inUseBytes;
    OE_TEST(oe_get_malloc_stats(&stats) == OE_OK);
    inUseBytes = stats.inUseBytes;

    /* Run the tests */
    TestEC();
    TestRandom();
    TestRSA();
    TestSHA();

    /* Verify that all malloc'd memory has been released */
    OE_TEST(oe_get_malloc_stats(&stats) == OE_OK);
    if (stats.inUseBytes > inUseBytes)
    {
        fprintf(
            stderr,
            "ERROR: memory leaked: %lu bytes\n",
            stats.inUseBytes - inUseBytes);
        oe_abort();
    }
}
