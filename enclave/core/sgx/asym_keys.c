// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/raise.h>
#include "internal_t.h"
#include "upcalls.h"

oe_result_t oe_get_public_key_ecall(
    const oe_asymmetric_key_params_t* key_params,
    const void* key_info,
    size_t key_info_size,
    void* key_buffer,
    size_t key_buffer_size,
    size_t* key_buffer_size_out)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!oe_get_public_key_upcall)
        OE_RAISE(OE_FAILURE);

    OE_CHECK((*oe_get_public_key_upcall)(
        key_params,
        key_info,
        key_info_size,
        key_buffer,
        key_buffer_size,
        key_buffer_size_out));

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_get_public_key_by_policy_ecall(
    uint32_t seal_policy,
    const oe_asymmetric_key_params_t* key_params,
    void* key_buffer,
    size_t key_buffer_size,
    size_t* key_buffer_size_out,
    void* key_info,
    size_t key_info_size,
    size_t* key_info_size_out)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!oe_get_public_key_by_policy_upcall)
        OE_RAISE(OE_FAILURE);

    OE_CHECK((*oe_get_public_key_by_policy_upcall)(
        seal_policy,
        key_params,
        key_buffer,
        key_buffer_size,
        key_buffer_size_out,
        key_info,
        key_info_size,
        key_info_size_out));

    result = OE_OK;

done:
    return result;
}
