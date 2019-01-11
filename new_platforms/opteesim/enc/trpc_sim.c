/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <tee_api.h>
#include <tee_ta_api.h>
#include <pta_rpc.h>
#include <string.h>
#include <pta_cyres.h>
#include "cyres_sim.h"

__declspec(dllexport)
TEE_Result TEE_OpenTASession_Export(
    const TEE_UUID *destination,
    uint32_t cancellationRequestTimeout,
    uint32_t paramTypes,
    TEE_Param params[TEE_NUM_PARAMS],
    TEE_TASessionHandle *session,
    uint32_t *returnOrigin)
{
    return TEE_OpenTASession(destination, cancellationRequestTimeout, paramTypes,
        params, session, returnOrigin);
}

typedef TEE_Result (*InvokeREECallbackProc)(
    uint32_t commandID,
    uint32_t paramTypes,
    TEE_Param params[TEE_NUM_PARAMS]);
InvokeREECallbackProc g_InvokeREECallback = NULL;

__declspec(dllexport)
void TEE_SetREECallback(InvokeREECallbackProc proc)
{
    g_InvokeREECallback = proc;
}

#define MOCK_PTA_SESSION ((TEE_TASessionHandle)0x87654321)
#define MOCK_CYRES_PTA_SESSION ((TEE_TASessionHandle)((uint32_t)MOCK_PTA_SESSION+1))

TEE_Result TEE_OpenTASession(
    _In_opt_ const TEE_UUID *destination,
    _In_ uint32_t cancellationRequestTimeout,
    _In_ uint32_t paramTypes,
    _In_ TEE_Param params[TEE_NUM_PARAMS],
    _In_ TEE_TASessionHandle *session,
    _Out_ uint32_t *returnOrigin)
{
    static const TEE_UUID pta_uuid = PTA_RPC_UUID;
    static const TEE_UUID pta_cyres_uuid = PTA_CYRES_UUID;
    TEE_Result res = TEE_SUCCESS;
    
    *session = NULL;

    if (destination != NULL) {
        if (memcmp(&pta_uuid, destination, sizeof(pta_uuid)) == 0) {
            /* This is an OCALL session to the PTA. */
            *session = MOCK_PTA_SESSION;
            return TEE_SUCCESS;
        }
        else if (memcmp(&pta_cyres_uuid, destination, sizeof(pta_uuid) ) == 0) {
            *session = MOCK_CYRES_PTA_SESSION;
            return TEE_SUCCESS;
        }
    }

    // TODO: move this to DllMain
    res = TA_CreateEntryPoint();
    if (res != TEE_SUCCESS) {
        return res;
    }

    res = TA_OpenSessionEntryPoint(paramTypes, params, session);
    
    return res;
}

__declspec(dllexport)
TEE_Result TEE_InvokeTACommand_Export(
    TEE_TASessionHandle session,
    uint32_t cancellationRequestTimeout,
    uint32_t commandID,
    uint32_t paramTypes,
    TEE_Param params[TEE_NUM_PARAMS],
    uint32_t *returnOrigin)
{
    return TEE_InvokeTACommand(session, cancellationRequestTimeout, commandID, paramTypes, params, returnOrigin);
}

TEE_Result TEE_InvokeTACommand(
    TEE_TASessionHandle session,
    uint32_t cancellationRequestTimeout,
    uint32_t commandID, 
    uint32_t paramTypes,
    TEE_Param params[TEE_NUM_PARAMS],
    uint32_t *returnOrigin)
{
    if (session == MOCK_PTA_SESSION) {
        /* Handle an OCALL, which is implemented in OP-TEE by
         * a TA-to-TA "ECALL" to OP-TEE's pseudo-TA.  Here, we
         * take a shortcut and just call the REE handler, like
         * the pseudo-TA would do.
         */
        return g_InvokeREECallback(commandID, paramTypes, params);
    }

    if (session == MOCK_CYRES_PTA_SESSION) {
        /* Handle an call to the CYRES PTA. */
        return invoke_cyres_pta(commandID, paramTypes, params);
    }

    /* Handle an ECALL. */
    return TA_InvokeCommandEntryPoint(session, commandID, paramTypes, params);
}
