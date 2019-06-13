// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/enclave.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <pta_cyres.h>

#include "globals.h"

oe_result_t _get_oe_result_from_tee_result(TEE_Result status)
{
    switch (status)
    {
        case TEE_SUCCESS:
            return OE_OK;

        case TEE_ERROR_SHORT_BUFFER:
            return OE_BUFFER_TOO_SMALL;

        case TEE_ERROR_BAD_PARAMETERS:
            return OE_INVALID_PARAMETER;

        case TEE_ERROR_OUT_OF_MEMORY:
            return OE_OUT_OF_MEMORY;

        case TEE_ERROR_NOT_SUPPORTED:
            return OE_UNSUPPORTED;

        case TEE_ERROR_ITEM_NOT_FOUND:
            return OE_NOT_FOUND;

        case TEE_ERROR_BUSY:
            return OE_BUSY;

        case TEE_ERROR_COMMUNICATION:
            return OE_SERVICE_UNAVAILABLE;

        default:
            return OE_FAILURE;
    }
}

static void* _find_terminator(uint8_t* buf, size_t buf_size)
{
    while (buf < (buf + buf_size))
        if (buf++ == '\0')
            return buf;

    return NULL;
}

static TEE_Result _get_cyres_pta_buffer(
    uint32_t cmd_id,
    uint8_t* buf,
    uint32_t* buf_size)
{
    TEE_Result result;

    uint32_t param_types;
    TEE_Param params[TEE_NUM_PARAMS] = {0};

    if (__oe_cyres_pta_session == TEE_HANDLE_NULL)
        return TEE_ERROR_COMMUNICATION;

    *buf_size = 0;

    param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    params[0].memref.buffer = buf;
    params[0].memref.size = *buf_size;

    result = TEE_InvokeTACommand(
        __oe_cyres_pta_session, 0, cmd_id, param_types, params, NULL);
    if (result != TEE_SUCCESS)
    {
        if (result == TEE_ERROR_SHORT_BUFFER)
            *buf_size = params[0].memref.size;

        return result;
    }

    *buf_size = params[0].memref.size;

    return TEE_SUCCESS;
}

static TEE_Result _get_cyres_pta_allocated_buf(
    uint32_t cmd_id,
    uint8_t** buf,
    size_t* buf_size)
{
    TEE_Result result;

    uint32_t local_buf_size;
    uint8_t* local_buf = NULL;

    /* Get the data size */
    result = _get_cyres_pta_buffer(cmd_id, NULL, &local_buf_size);
    if (result != TEE_ERROR_SHORT_BUFFER)
        goto done;

    oe_assert(local_buf_size != 0);

    /* Allocate memory locally and request the data */
    local_buf = oe_calloc(1, local_buf_size);
    if (local_buf == NULL)
    {
        result = TEE_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    result = _get_cyres_pta_buffer(cmd_id, local_buf, &local_buf_size);
    if (result != TEE_SUCCESS)
        goto done;

    *buf_size = local_buf_size;
    *buf = local_buf;
    local_buf = NULL;

    result = TEE_SUCCESS;

done:
    oe_free(local_buf);
    return result;
}

oe_result_t oe_get_cyres_seal_secret(
    const uint8_t* key_selector,
    size_t key_selector_size,
    uint8_t** secret,
    size_t* secret_size,
    size_t req_size)
{
    oe_result_t result;
    TEE_Result tee_result;

    uint32_t param_types;
    TEE_Param params[TEE_NUM_PARAMS] = {0};

    uint8_t* local_secret;

    if (__oe_cyres_pta_session == TEE_HANDLE_NULL)
        return OE_SERVICE_UNAVAILABLE;

    if (key_selector_size == 0 || key_selector == NULL || secret_size == 0 ||
        secret == NULL)
        return OE_INVALID_PARAMETER;

    if (req_size > OE_UINT32_MAX || key_selector_size > OE_UINT32_MAX)
        return OE_OUT_OF_BOUNDS;

    param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    local_secret = oe_malloc(req_size);
    if (local_secret == NULL)
        goto done;

    params[0].memref.buffer = local_secret;
    params[0].memref.size = (uint32_t)req_size;
    params[1].memref.buffer = (uint8_t*)key_selector;
    params[1].memref.size = (uint32_t)key_selector_size;

    tee_result = TEE_InvokeTACommand(
        __oe_cyres_pta_session,
        0,
        PTA_CYRES_GET_SEAL_KEY,
        param_types,
        params,
        NULL);
    if (tee_result != TEE_SUCCESS)
    {
        result = _get_oe_result_from_tee_result(tee_result);
        goto done;
    }

    *secret = local_secret;
    *secret_size = req_size;
    local_secret = NULL;

done:
    oe_free(local_secret);
    return result;
}

oe_result_t oe_get_cyres_private_key(uint8_t** pem, size_t* pem_size)
{
    TEE_Result tee_result;

    tee_result =
        _get_cyres_pta_allocated_buf(PTA_CYRES_GET_PRIVATE_KEY, pem, pem_size);
    if (tee_result != TEE_SUCCESS)
        return _get_oe_result_from_tee_result(tee_result);

    /* PEM format, should have a zero terminator */
    oe_assert(_find_terminator(*pem, *pem_size) != NULL);
    return OE_OK;
}

oe_result_t oe_get_cyres_public_key(uint8_t** pem, size_t* pem_size)
{
    TEE_Result tee_result;

    tee_result =
        _get_cyres_pta_allocated_buf(PTA_CYRES_GET_PUBLIC_KEY, pem, pem_size);
    if (tee_result != TEE_SUCCESS)
        return _get_oe_result_from_tee_result(tee_result);

    /* PEM format, should have a zero terminator */
    oe_assert(_find_terminator(*pem, *pem_size) != NULL);
    return OE_OK;
}

oe_result_t oe_get_cyres_cert_chain(uint8_t** pem, size_t* pem_size)
{
    TEE_Result tee_result;

    tee_result =
        _get_cyres_pta_allocated_buf(PTA_CYRES_GET_CERT_CHAIN, pem, pem_size);
    if (tee_result != TEE_SUCCESS)
        return _get_oe_result_from_tee_result(tee_result);

    /* PEM format, should have a zero terminator */
    oe_assert(_find_terminator(*pem, *pem_size) != NULL);
    return OE_OK;
}
