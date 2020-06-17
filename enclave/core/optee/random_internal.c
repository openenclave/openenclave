// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define OE_NEED_STDC_NAMES
#include <openenclave/enclave.h>

#include <tee_internal_api.h>

oe_result_t oe_random_internal(void* data, size_t size)
{
    if (size > OE_UINT32_MAX)
        return OE_OUT_OF_BOUNDS;

    TEE_GenerateRandom(data, (uint32_t)size);

    return OE_OK;
}
