/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <malloc.h>
#include <openenclave/enclave.h>
#include "../oeresult.h"

/* TODO: use a cyrep-derived key and remove */
#define MOCK_KEY_SIZE 16
typedef struct mock_key_info_t {
    uint8_t seed[MOCK_KEY_SIZE];
    oe_seal_policy_t policy;
}mock_key_info_t;

oe_result_t oe_get_seal_key_by_policy_v2(
    _In_ oe_seal_policy_t seal_policy,
    _Outptr_ uint8_t** key_buffer,
    _Out_ size_t* key_buffer_size,
    _Outptr_opt_ uint8_t** key_info,
    _Out_ size_t* key_info_size)
{
    if (seal_policy == 0) {
        return OE_INVALID_PARAMETER;
    }

    mock_key_info_t* info = malloc(sizeof(mock_key_info_t));
    if (info == NULL) {
        return OE_OUT_OF_MEMORY;
    }
    /* TODO: use a cyrep-derived key */
    oe_result_t oeResult = oe_random(info->seed, sizeof(MOCK_KEY_SIZE));
    if (oeResult != OE_OK) {
        free(info);
        return oeResult;
    }

    info->policy = seal_policy;
    if (key_info != NULL) {
        *key_info = info;
        *key_info_size = sizeof(mock_key_info_t);
    }
    return oe_get_seal_key_v2(info, sizeof(mock_key_info_t), key_buffer, key_buffer_size);
}

oe_result_t oe_get_seal_key_v2(
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size)
{
    if (key_info_size != sizeof(mock_key_info_t)) {
        return OE_INVALID_PARAMETER;
    }
    *key_buffer = malloc(MOCK_KEY_SIZE);
    if (*key_buffer == NULL) {
        return OE_OUT_OF_MEMORY;
    }

    mock_key_info_t* info = key_info;
    *key_buffer_size = MOCK_KEY_SIZE;
    /* TODO: use a cyrep-derived key */
    memcpy(*key_buffer, info->seed, *key_buffer_size);
    return OE_OK;
}

oe_result_t oe_get_public_key_by_policy(
    oe_seal_policy_t seal_policy,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size)
{
    /* TODO: use a cyrep-derived key */
    return oe_get_seal_key_by_policy_v2(seal_policy, key_buffer, key_buffer_size, key_info, key_info_size);
}

 oe_result_t oe_get_public_key(
     const uint8_t* key_info,
     size_t key_info_size,
     uint8_t** key_buffer,
     size_t* key_buffer_size)
 {
     /* TODO: use a cyrep-derived key */
    return oe_get_seal_key_v2(key_info, key_info_size, key_buffer, key_buffer_size);
 }

 oe_result_t oe_get_private_key_by_policy(
     oe_seal_policy_t seal_policy,
     uint8_t** key_buffer,
     size_t* key_buffer_size,
     uint8_t** key_info,
     size_t* key_info_size)
 {
     /* TODO: use a cyrep-derived key */
    return oe_get_seal_key_by_policy_v2(seal_policy, key_buffer, key_buffer_size, key_info, key_info_size);
 }

 oe_result_t oe_get_private_key(
     const uint8_t* key_info,
     size_t key_info_size,
     uint8_t** key_buffer,
     size_t* key_buffer_size)
 {
     /* TODO: use a cyrep-derived key */
    return oe_get_seal_key_v2(key_info, key_info_size, key_buffer, key_buffer_size);
 }