// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License

#include <openenclave/bits/result.h>
#include <openenclave/host.h>
#include <openenclave/internal/asym_keys.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

oe_result_t oe_get_public_key_by_policy(
    oe_enclave_t* enclave,
    oe_seal_policy_t seal_policy,
    const oe_asymmetric_key_params_t* key_params,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_public_key_by_policy_args_t args;

    if (!key_buffer || !key_buffer_size || !key_info || !key_info_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Setup input params. */
    args.seal_policy = seal_policy;
    args.key_params = *key_params;

    OE_CHECK(
        oe_ecall(
            enclave, OE_ECALL_GET_PUBLIC_KEY_BY_POLICY, (uint64_t)&args, NULL));

    /* Set the output params. */
    *key_buffer = args.key_buffer;
    *key_buffer_size = args.key_buffer_size;
    *key_info = args.key_info;
    *key_info_size = args.key_info_size;

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_get_public_key(
    oe_enclave_t* enclave,
    const oe_asymmetric_key_params_t* key_params,
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_public_key_args_t args;

    if (!key_buffer || !key_buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Setup input params. */
    args.key_params = *key_params;
    args.key_info = key_info;
    args.key_info_size = key_info_size;

    OE_CHECK(oe_ecall(enclave, OE_ECALL_GET_PUBLIC_KEY, (uint64_t)&args, NULL));

    /* Set the output params. */
    *key_buffer = args.key_buffer;
    *key_buffer_size = args.key_buffer_size;

    result = OE_OK;

done:
    return result;
}

void oe_free_key(
    uint8_t* key_buffer,
    size_t key_buffer_size,
    uint8_t* key_info,
    size_t key_info_size)
{
    if (key_buffer)
    {
        oe_secure_zero_fill(key_buffer, key_buffer_size);
        free(key_buffer);
    }

    if (key_info)
    {
        oe_secure_zero_fill(key_info, key_buffer_size);
        free(key_info);
    }
}
