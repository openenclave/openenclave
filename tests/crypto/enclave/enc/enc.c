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

#define BUILD_ENCLAVE
#include "../../tests.c"

OE_ECALL void Test(void* args_)
{
    /* Save the current malloc'c bytes in use */
    uint64_t inUseBytes;
    {
        OE_MallocStats stats;

        if (OE_GetMallocStats(&stats) != 0)
            OE_TEST("OE_GetMallocStats() failed" == NULL);

        inUseBytes = stats.inUseBytes;
    }

    RunAllTests();

    /* Verify that all malloc'c memory has been released */
    {
        OE_MallocStats stats;

        if (OE_GetMallocStats(&stats) != 0)
            OE_TEST("OE_GetMallocStats() failed" == NULL);

        if (stats.inUseBytes != inUseBytes)
        {
            printf("*** ERROR: bytes in use: %lu\n", stats.inUseBytes);
            OE_Abort();
        }
    }
}
