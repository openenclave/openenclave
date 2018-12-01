/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdlib.h>
#include <string.h>
#include <pta_cyres.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <openenclave/enclave.h>

#include "cyres_optee.h"
#include "enclavelibc.h"
#include "oeresult_optee.h"

static TEE_Result call_cyres_pta(
    uint32_t cmd_id,
    uint32_t param_types,
    TEE_Param params[TEE_NUM_PARAMS])
{
    static TEE_TASessionHandle sess = TEE_HANDLE_NULL;
    static const TEE_UUID pta_uuid = PTA_CYRES_UUID;
    TEE_Result result = TEE_SUCCESS;

    if (sess == TEE_HANDLE_NULL)
    {
        result = TEE_OpenTASession(&pta_uuid, 0, 0, NULL, &sess, NULL);
        if (result != TEE_SUCCESS)
            return get_oe_result_from_tee_result(result);
    }

    result = TEE_InvokeTACommand(sess, 0, cmd_id, param_types, params, NULL);
    return get_oe_result_from_tee_result(result);
}

static TEE_Result get_pta_buf(uint32_t cmd_id, uint8_t* buf, uint32_t* buf_size)
{
    uint32_t pt;
    TEE_Param params[TEE_NUM_PARAMS];
    oe_result_t oe_result;

    if (buf_size == NULL)
        return OE_INVALID_PARAMETER;

    if (buf == NULL)
        *buf_size = 0;

    pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);
    memset(params, 0, sizeof(params));

    /* Null indicates request for required size */
    if (buf != NULL)
    {
        params[0].memref.buffer = buf;
    }
    params[0].memref.size = *buf_size;

    oe_result = call_cyres_pta(cmd_id, pt, params);
    if (oe_result != OE_OK)
    {
        if (oe_result == OE_BUFFER_TOO_SMALL)
            *buf_size = params[0].memref.size;
        return oe_result;
    }

    *buf_size = params[0].memref.size;
    return OE_OK;
}

/* Common PTA routine for buffer retrival commands */
static TEE_Result get_pta_allocated_buf(
    uint32_t cmd_id,
    uint8_t** buf,
    uint32_t* buf_size)
{
    oe_result_t oe_result;
    uint32_t local_buf_size;
    uint8_t* local_buf = NULL;

    /* Get the data size */
    oe_result = get_pta_buf(cmd_id, NULL, &local_buf_size);
    if (oe_result != OE_BUFFER_TOO_SMALL)
        goto done;

    oe_assert(local_buf_size != 0);

    /* Allocate memory locally and request the data */
    local_buf = oe_malloc(local_buf_size);
    if (local_buf == NULL)
    {
        oe_result = OE_OUT_OF_MEMORY;
        goto done;
    }
    memset(local_buf, 0, local_buf_size);

    oe_result = get_pta_buf(cmd_id, local_buf, &local_buf_size);
    if (oe_result != OE_OK)
        goto done;

    oe_result = OE_OK;
    *buf_size = local_buf_size;
    *buf = local_buf;
    /* Remember to clear the local reference on success */
    local_buf = NULL;

done:
    oe_free(local_buf);
    return oe_result;
}

oe_result_t get_cyres_seal_secret(
    const uint8_t* key_selector,
    size_t key_selector_size,
    uint8_t** secret,
    size_t* secret_size,
    size_t req_size)
{
    uint32_t pt;
    TEE_Param params[TEE_NUM_PARAMS];
    oe_result_t oeResult;
    uint8_t* local_secret = NULL;

    if (key_selector_size == 0 || key_selector == NULL || secret_size == 0 ||
        secret == NULL)
        return OE_INVALID_PARAMETER;

    pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);
    memset(params, 0, sizeof(params));

    local_secret = oe_malloc(req_size);
    if (local_secret == NULL)
        goto done;

    params[0].memref.buffer = local_secret;
    params[0].memref.size = req_size;
    params[1].memref.buffer = (uint8_t*)key_selector;
    params[1].memref.size = key_selector_size;

    oeResult = call_cyres_pta(PTA_CYRES_GET_SEAL_KEY, pt, params);
    if (oeResult != OE_OK)
        goto done;

    *secret = local_secret;
    *secret_size = req_size;
    local_secret = NULL;

done:
    free(local_secret);
    return oeResult;
}

oe_result_t get_cyres_private_key(uint8_t** pem, size_t* pem_size)
{
    oe_result_t oe_result =
        get_pta_allocated_buf(PTA_CYRES_GET_PRIVATE_KEY, pem, pem_size);
    if (oe_result != OE_OK)
        return oe_result;

    /* PEM format, should have a zero terminator */
    oe_assert((*pem)[(*pem_size) - 1] == '\0');
    return OE_OK;
}

oe_result_t get_cyres_public_key(uint8_t** pem, size_t* pem_size)
{
    oe_result_t oe_result =
        get_pta_allocated_buf(PTA_CYRES_GET_PUBLIC_KEY, pem, pem_size);
    if (oe_result != OE_OK)
        return oe_result;

    /* PEM format, should have a zero terminator */
    oe_assert((*pem)[(*pem_size) - 1] == '\0');
    return OE_OK;
}

oe_result_t get_cyres_cert_chain(uint8_t** pem, size_t* pem_size)
{
    oe_result_t oe_result =
        get_pta_allocated_buf(PTA_CYRES_GET_CERT_CHAIN, pem, pem_size);
    if (oe_result != OE_OK)
        return oe_result;

    /* PEM format, should have a zero terminator */
    oe_assert((*pem)[(*pem_size) - 1] == '\0');
    return OE_OK;
}

#ifdef DISABLE /* Disable file export for now. Not used by OE */
oe_result_t ExportCyresCertChain(Tcps_ConstStringA exportFilePath)
{
    Tcps_UInt32 certChainBufferSize;
    char* certChainBufferPEM = NULL;

    Tcps_InitializeStatus(Tcps_Module_Helper_t, "ExportCyresCertChain");

    /* Get the chain size */
    uStatus = get_cyres_cert_chain(&certChainBufferPEM, &certChainBufferSize);
    Tcps_GotoErrorIfBad(uStatus);

    /* Export the cert chain into an untrusted-world file */
    uStatus = TEE_P_ExportFile(
        exportFilePath, certChainBufferPEM, certChainBufferSize);
    Tcps_GotoErrorIfBad(uStatus);

    if (certChainBufferPEM != NULL)
    {
        oe_free(certChainBufferPEM);
    }

    Tcps_ReturnStatusCode;
    Tcps_BeginErrorHandling;
    if (certChainBufferPEM != NULL)
    {
        oe_free(certChainBufferPEM);
    }
    Tcps_FinishErrorHandling;
}
#endif
