// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define OE_NEED_STDC_NAMES
#include <openenclave/enclave.h>
#include <openenclave/internal/entropy.h>

#include <tee_internal_api.h>

oe_result_t oe_get_entropy(void* output, size_t len, oe_entropy_kind_t* kind)
{
    if (len > OE_UINT32_MAX)
        return OE_OUT_OF_BOUNDS;

    TEE_GenerateRandom(output, (uint32_t)len);
    *kind = OE_ENTROPY_KIND_OPTEE;
    return OE_OK;
}
