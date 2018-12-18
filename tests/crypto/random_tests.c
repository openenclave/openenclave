// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(OE_BUILD_ENCLAVE)
#include <openenclave/enclave.h>
#endif

#include <openenclave/internal/random.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include "tests.h"

void TestRandom(void)
{
    printf("=== begin %s()\n", __FUNCTION__);

    static const size_t N = 64;
    static const size_t M = 19;
    uint8_t buf[N][M];

    memset(buf, 0, sizeof(buf));

    for (size_t i = 0; i < N; i++)
    {
        /* Generate a random sequence */
        OE_TEST(oe_random_internal(buf[i], M * sizeof(uint8_t)) == OE_OK);

        /* Be sure buffer is not filled with same character */
        {
            size_t m;
            uint8_t c = buf[i][0];

            for (m = 1; m < M && buf[i][m] == c; m++)
                ;

            OE_TEST(m != M);
        }

        /* Check whether duplicate of one of the previous calls */
        for (size_t j = 0; j < i; j++)
        {
            OE_TEST(memcmp(buf[j], buf[i], M * sizeof(uint8_t)) != 0);
        }
    }

    printf("=== passed %s()\n", __FUNCTION__);
}
