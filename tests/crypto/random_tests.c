// Copyright (c) Open Enclave SDK contributors.
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

static void _test_random(size_t seq_length)
{
    printf("=== begin %s(%zu)\n", __FUNCTION__, seq_length);

    uint8_t buf[SEQ_COUNT][seq_length];
    memset(buf, 0, sizeof(buf));

    for (size_t i = 0; i < SEQ_COUNT; i++)
    {
        /* Generate a random sequence */
        OE_TEST(
            oe_random_internal(buf[i], seq_length * sizeof(uint8_t)) == OE_OK);

        /* Be sure buffer is not filled with same character */
        {
            size_t m;
            uint8_t c = buf[i][0];

            for (m = 1; m < seq_length && buf[i][m] == c; m++)
                ;

            OE_TEST(m != seq_length);
        }

        /* Check whether duplicate of one of the previous calls */
        for (size_t j = 0; j < i; j++)
        {
            OE_TEST(memcmp(buf[j], buf[i], seq_length * sizeof(uint8_t)) != 0);
        }
    }

    printf("=== passed %s()\n", __FUNCTION__);
}

void TestRandom(void)
{
    _test_random(19);
    _test_random(1023);
    _test_random(1024);
    _test_random(1025);
    _test_random(2047);
    _test_random(2048);
    _test_random(2049);
}
