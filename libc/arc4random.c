// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/* Ignore unused-variable warning in system header */
#pragma GCC diagnostic ignored "-Wunused-variable"
#include <stdlib.h>
/*
 * Random implementation needed by libcxx as alternative to device oriented
 * randomness (/dev/rand)
 */

unsigned int arc4random(void)
{
    unsigned int r;

    while (!__builtin_ia32_rdrand32_step(&r))
        ;
    return r;
}
