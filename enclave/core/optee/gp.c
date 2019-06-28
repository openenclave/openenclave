// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <tee_internal_api.h>

TEE_Result TA_CreateEntryPoint(void)
{
    return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint(
    uint32_t param_types,
    TEE_Param params[4],
    void** sess_ctx)
{
    OE_UNUSED(param_types);
    OE_UNUSED(params);
    OE_UNUSED(sess_ctx);
    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(
    void* sess_ctx,
    uint32_t cmd_id,
    uint32_t param_types,
    TEE_Param params[4])
{
    OE_UNUSED(sess_ctx);
    OE_UNUSED(cmd_id);
    OE_UNUSED(param_types);
    OE_UNUSED(params);
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void* sess_ctx)
{
    OE_UNUSED(sess_ctx);
}

void TA_DestroyEntryPoint(void)
{
}
