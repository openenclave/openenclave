// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <tee_internal_api.h>

/*
 * Random implementation needed by libcxx as alternative to device oriented
 * randomness (/dev/rand)
 */

unsigned int arc4random(void)
{
    unsigned int r;

    TEE_GenerateRandom(&r, sizeof(r));

    return r;
}
