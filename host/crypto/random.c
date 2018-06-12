// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/random.h>
#include <openssl/rand.h>

OE_Result OE_Random(void* data, size_t size)
{
    if (!RAND_bytes(data, size))
        return OE_FAILURE;

    return OE_OK;
}
