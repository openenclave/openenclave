// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/random.h>
#include <openssl/rand.h>

oe_result_t oe_random_internal(void* data, size_t size)
{
    if (!RAND_bytes(data, size))
        return OE_FAILURE;

    return OE_OK;
}
