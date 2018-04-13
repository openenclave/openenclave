// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <immintrin.h>
#include <stdlib.h>
/*
 * Random implementation needed by libcxx as alternative to device oriented
 * randomness (/dev/rand)
 */

unsigned int arc4random(void)
{
    unsigned int r;

    while (!_rdrand32_step(&r))
        ;
    return r;
}
