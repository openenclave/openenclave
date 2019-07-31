// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(OE_BUILD_ENCLAVE)
#include <openenclave/enclave.h>
#endif

#include <openenclave/internal/random.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"

#define SEQ_COUNT 64
#define SEQ_LENGTH 19

void TestRandom(void)
{
    printf("=== begin %s()\n", __FUNCTION__);

    uint8_t buf[SEQ_COUNT][SEQ_LENGTH];
    memset(buf, 0, sizeof(buf));

    for (size_t i = 0; i < SEQ_COUNT; i++)
    {
        /* Generate a random sequence */
        OE_TEST(
            oe_random_internal(buf[i], SEQ_LENGTH * sizeof(uint8_t)) == OE_OK);

        /* Be sure buffer is not filled with same character */
        {
            size_t m;
            uint8_t c = buf[i][0];

            for (m = 1; m < SEQ_LENGTH && buf[i][m] == c; m++)
                ;

            OE_TEST(m != SEQ_LENGTH);
        }

        /* Check whether duplicate of one of the previous calls */
        for (size_t j = 0; j < i; j++)
        {
            OE_TEST(memcmp(buf[j], buf[i], SEQ_LENGTH * sizeof(uint8_t)) != 0);
        }
    }

    printf("=== passed %s()\n", __FUNCTION__);
}
