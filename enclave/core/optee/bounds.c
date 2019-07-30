// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/enclave.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

bool oe_is_within_enclave(const void* ptr, size_t sz)
{
    TEE_Result result;

    if (sz >= OE_UINT32_MAX)
        return false;

    /* TEE_CheckMemoryAccessRights takes a shortcut when size is zero and
     * assumes the pointer in question is inside the TA when it might in fact
     * refer to a location outside of it.
     *
     * TODO: Are there any instances where overriding the value may be used
     *       against the TA?
     */
    if (sz == 0)
        sz = 1;

    result = TEE_CheckMemoryAccessRights(
        TEE_MEMORY_ACCESS_SECURE, (void*)ptr, (uint32_t)sz);
    return result == TEE_SUCCESS;
}

bool oe_is_outside_enclave(const void* ptr, size_t sz)
{
    return !oe_is_within_enclave(ptr, sz);
}
