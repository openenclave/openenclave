// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/bits/cert.h>
#include <openenclave/bits/ec.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/malloc.h>
#include <openenclave/bits/random.h>
#include <openenclave/bits/rsa.h>
#include <openenclave/bits/sha.h>
#include <openenclave/bits/tests.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef NDEBUG
#include "../../../../enclave/refs.h"
#endif

#define BUILD_ENCLAVE
#include "../../tests.c"

OE_ECALL void Test(void* args_)
{
    OE_MallocStats stats;

    /* Save the current malloc'd bytes in use */
    uint64_t inUseBytes;
    OE_TEST(OE_GetMallocStats(&stats) == OE_OK);
    inUseBytes = stats.inUseBytes;

    RunAllTests();

    /* Verify that all malloc'd memory has been released */
    OE_TEST(OE_GetMallocStats(&stats) == OE_OK);
    if (stats.inUseBytes > inUseBytes)
    {
        fprintf(stderr, "ERROR: memory leaked: %lu bytes\n", 
            stats.inUseBytes - inUseBytes);
        OE_Abort();
    }

#ifndef NDEBUG
    /* Verify that all crypto objects have been released */
    {
        const uint64_t refs = OE_RefsGet();

        if (refs != 0)
        {
            fprintf(stderr, "ERROR: objects leaked: %lu\n", refs);
            OE_Abort();
        }
    }
#endif
}
