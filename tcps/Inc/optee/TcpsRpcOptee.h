/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef TRUSTED_CODE
# error TcpsRpcOptee.h should only be included with TRUSTED_CODE
#endif
#ifndef USE_OPTEE
# error TcpsRpcOptee.h should only be included with USE_OPTEE
#endif

#ifdef _MSC_VER
#pragma warning( push )  
#pragma warning( disable : 4200 )  
#pragma warning( disable : 4201 )  
#endif
#include <tee_api_types.h>
#ifdef _MSC_VER
#pragma warning( pop ) 
#endif
#include <sgx_error.h>

TEE_Result
TcpsEcallDemux(
    void *sess_ctx,
    uint32_t cmd_id,
    uint32_t param_types,
    TEE_Param params[4]);

sgx_status_t
sgx_optee_ocall(
    const unsigned int index,
    void* buffer,
    size_t bufferSize);
