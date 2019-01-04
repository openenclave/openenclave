/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <assert.h>
#include <malloc.h>
#include <openenclave/enclave.h>
#include <stdint.h>
#include <string.h>
#include "cyres_optee.h"
#include "enclavelibc.h"

/* Key selector size used when deriving a new sealing secret */
#define KEY_SELECTOR_SIZE 32

/* Size of the desired sealing secret */
#define SEAL_SECRET_SIZE 32

typedef struct cyres_key_info_t
{
    uint8_t key_selector[KEY_SELECTOR_SIZE];
    oe_seal_policy_t policy;
} seal_info_t;

oe_result_t oe_get_seal_key_by_policy_v2(
    _In_ oe_seal_policy_t seal_policy,
    _Outptr_ uint8_t** key_buffer,
    _Out_ size_t* key_buffer_size,
    _Outptr_opt_ uint8_t** key_info,
    _Out_ size_t* key_info_size)
{
    oe_result_t oe_result;
    seal_info_t* info = NULL;

    if (seal_policy == 0)
    {
        oe_result = OE_INVALID_PARAMETER;
        goto done;
    }

    if (seal_policy == OE_SEAL_POLICY_PRODUCT)
    {
        oe_result = OE_UNSUPPORTED;
        goto done;
    }

    info = (seal_info_t*)oe_malloc(sizeof(seal_info_t));
    if (info == NULL)
    {
        oe_result = OE_OUT_OF_MEMORY;
        goto done;
    }

    /* Generate key selector */
    oe_result = oe_random(info->key_selector, sizeof(info->key_selector));
    if (oe_result != OE_OK)
        goto done;

    oe_result = oe_get_seal_key_v2(
        (uint8_t*)info, sizeof(seal_info_t), key_buffer, key_buffer_size);
    if (oe_result != OE_OK)
        goto done;

    if (key_info == NULL)
    {
        oe_result = OE_OK;
        goto done;
    }

    /* Copy out the key creation info */
    info->policy = seal_policy;
    *key_info = (uint8_t*)info;
    info = NULL;
    *key_info_size = sizeof(seal_info_t);

done:
    free(info);
    return oe_result;
}

oe_result_t oe_get_seal_key_v2(
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size)
{
    if (key_buffer == NULL || key_buffer_size == NULL || key_info == NULL ||
        key_info_size != sizeof(seal_info_t))
        return OE_INVALID_PARAMETER;

    const seal_info_t* info = (const seal_info_t*)key_info;
    return get_cyres_seal_secret(
        info->key_selector,
        sizeof(info->key_selector),
        key_buffer,
        key_buffer_size,
        KEY_SELECTOR_SIZE);
}

oe_result_t oe_get_public_key_by_policy(
    oe_seal_policy_t seal_policy,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size)
{
    if (seal_policy == 0)
        return OE_INVALID_PARAMETER;

    if (seal_policy == OE_SEAL_POLICY_PRODUCT)
        return OE_UNSUPPORTED;

    if (key_info != NULL)
    {
        oe_result_t oe_result = get_cyres_cert_chain(key_info, key_info_size);
        if (oe_result != OE_OK)
            return oe_result;
        return oe_get_public_key(
            *key_info, *key_info_size, key_buffer, key_buffer_size);
    }

    return oe_get_public_key(NULL, 0, key_buffer, key_buffer_size);
}

oe_result_t oe_get_public_key(
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size)
{
    if (key_buffer == NULL || key_buffer_size == NULL)
        return OE_INVALID_PARAMETER;

    return get_cyres_public_key(key_buffer, key_buffer_size);
}

oe_result_t oe_get_private_key_by_policy(
    oe_seal_policy_t seal_policy,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size)
{
    if (seal_policy == 0)
        return OE_INVALID_PARAMETER;

    if (seal_policy == OE_SEAL_POLICY_PRODUCT)
        return OE_UNSUPPORTED;

    if (key_info != NULL)
    {
        oe_result_t oe_result = get_cyres_cert_chain(key_info, key_info_size);
        if (oe_result != OE_OK)
            return oe_result;
        return oe_get_private_key(
            *key_info, *key_info_size, key_buffer, key_buffer_size);
    }

    return oe_get_private_key(NULL, 0, key_buffer, key_buffer_size);
}

oe_result_t oe_get_private_key(
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size)
{
    if (key_buffer == NULL || key_buffer_size == NULL)
        return OE_INVALID_PARAMETER;

    return get_cyres_private_key(key_buffer, key_buffer_size);
}
