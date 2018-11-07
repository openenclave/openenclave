/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#ifdef HAVE_CYREP
#include <pta_cyrep.h>
#endif
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <tcps.h>

#include <openenclave/enclave.h>
#include <sgx_utils.h>

#include "cyres-optee.h"

#define CYREP_MAX_RETRIES   10

#ifdef HAVE_CYREP
static TEE_Result 
CallCyrepPTA(
    uint32_t cmd_id,
	uint32_t param_types, 
	TEE_Param params[TEE_NUM_PARAMS])
{
	static TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	static const TEE_UUID pta_uuid = PTA_CYREP_UUID;
	TEE_Result result = TEE_SUCCESS;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "CallCyrepPTA");

	if (sess == TEE_HANDLE_NULL)
	{
		result = TEE_OpenTASession(&pta_uuid, 0, 0, NULL, &sess, NULL);
        DMSG("TEE_OpenTASession(PTA_CYREP) returned %#x", result);
        Tcps_GotoErrorIfTrue(result != TEE_SUCCESS, Tcps_Bad);
	}

	result = TEE_InvokeTACommand(sess, 0, cmd_id, param_types, params, NULL);
    FMSG("PTA_CYREP command %u returned %#x", cmd_id, result);
    Tcps_GotoErrorIfTrue(result != TEE_SUCCESS, Tcps_Bad);

    return result;

Tcps_BeginErrorHandling;
    oe_assert(result != TEE_SUCCESS);
    return result;
}

static
Tcps_StatusCode
GetCyrepCertChainSize(
    Tcps_UInt32 *certChainBufferSize)
{
    uint32_t pt;
    TEE_Param params[TEE_NUM_PARAMS];
    TEE_Result teeResult;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "GetCyrepCertChainSize");

    *certChainBufferSize = 0;

    pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);
	memset(params, 0, sizeof(params));

    teeResult = CallCyrepPTA(PTA_CYREP_GET_CERT_CHAIN_SIZE, pt, params);
    Tcps_GotoErrorIfTrue(teeResult != TEE_SUCCESS, Tcps_Bad);

    *certChainBufferSize = params[0].value.a;
    DMSG("Cyrep cert chain size = %u", *certChainBufferSize);

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
Tcps_FinishErrorHandling;
}

Tcps_StatusCode 
ExportCyrepCertChain(
    Tcps_ConstStringA exportFilePath)
{
    uint32_t pt;
    TEE_Result teeResult;
    Tcps_UInt32 certChainBufferSize;
    char *certChainBufferPEM = NULL;
    TEE_Param params[TEE_NUM_PARAMS];

Tcps_InitializeStatus(Tcps_Module_Helper_t, "ExportCyrepCertChain");

    /* Get the chain size */
    uStatus = GetCyrepCertChainSize(&certChainBufferSize);
    Tcps_GotoErrorIfBad(uStatus);
    oe_assert(certChainBufferSize != 0);

    /* Allocate memory and request the cert chain */
    certChainBufferPEM = oe_malloc(certChainBufferSize);
    Tcps_ReturnErrorIfAllocFailed(certChainBufferPEM);
    memset(certChainBufferPEM, 0, certChainBufferSize);

    pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INOUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);
    memset(params, 0, sizeof(params));

    params[0].memref.buffer = certChainBufferPEM;
    params[0].memref.size = certChainBufferSize;

    teeResult = CallCyrepPTA(PTA_CYREP_GET_CERT_CHAIN, pt, params);
    Tcps_GotoErrorIfTrue(teeResult != TEE_SUCCESS, Tcps_Bad);

    /* PEM format, should have a zero terminator */
    oe_assert(certChainBufferPEM[certChainBufferSize - 1] == 0);

    /* Export the cert chain into an untrusted-world file */
    uStatus = TEE_P_ExportFile(exportFilePath, certChainBufferPEM, certChainBufferSize);
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

static
Tcps_StatusCode
GetCyrepKeySize(
    Tcps_UInt32 *keySize)
{
    uint32_t pt;
    TEE_Result teeResult;
    TEE_Param params[TEE_NUM_PARAMS];

Tcps_InitializeStatus(Tcps_Module_Helper_t, "GetCyrepKeySize");

    *keySize = 0;

    pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);
	memset(params, 0, sizeof(params));

    teeResult = CallCyrepPTA(PTA_CYREP_GET_PRIVATE_KEY_SIZE, pt, params);
    Tcps_GotoErrorIfTrue(teeResult != TEE_SUCCESS, Tcps_Bad);

    *keySize = params[0].value.a;
    DMSG("Cyrep private key size = %u", *keySize);

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
Tcps_FinishErrorHandling;
}

Tcps_StatusCode 
GetCyrepKey(
    char **keyPEM)
{
    uint32_t pt;
    Tcps_UInt32 keySize;
    TEE_Param params[TEE_NUM_PARAMS];
    TEE_Result teeResult;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "GetCyrepKey");

    *keyPEM = NULL;

    /* Get the key size */
    uStatus = GetCyrepKeySize(&keySize);
    Tcps_GotoErrorIfBad(uStatus);
    oe_assert(keySize != 0);

    /* Allocate memory and request the key */
    *keyPEM = oe_malloc(keySize);
    Tcps_ReturnErrorIfAllocFailed(*keyPEM);
    memset(*keyPEM, 0, keySize);

    pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INOUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);
    memset(params, 0, sizeof(params));

    params[0].memref.buffer = *keyPEM;
    params[0].memref.size = keySize;

    teeResult = CallCyrepPTA(PTA_CYREP_GET_PRIVATE_KEY, pt, params);
    Tcps_GotoErrorIfTrue(teeResult != TEE_SUCCESS, Tcps_Bad);

    /* PEM format, should have a zero terminator */
    oe_assert((*keyPEM)[keySize - 1] == 0);

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
    if (*keyPEM != NULL)
    {
        oe_free(*keyPEM);
        *keyPEM = NULL;
    }
Tcps_FinishErrorHandling;
}
#endif // HAVE_CYREP

Tcps_Void
FreeCyrepKey(
    char *keyPEM)
{
    oe_assert(keyPEM != NULL);
    oe_free(keyPEM);
}
