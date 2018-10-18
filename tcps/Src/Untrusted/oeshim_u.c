/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <openenclave/bits/types.h>
#include <openenclave/host.h>
#include <tcps_u.h>
#include <sgx.h>
#include <Windows.h>
#include "TcpsCalls_u.h"
#include "../oeresult.h"

typedef struct {
    size_t nr_ocall;
    oe_call_t* call_addr;
} ocall_table_v2_t;

ocall_table_v2_t g_ocall_table_v2 = { 0 };

/* TODO: this flag should be per enclave */
int g_serialize_ecalls = FALSE;

/* TODO: this API is deprecated.  Remove once callers are changed. */
Tcps_StatusCode Tcps_CreateTA(
    _In_z_ const char* a_TaIdString,
    _In_ uint32_t a_Flags,
    _Out_ sgx_enclave_id_t* a_pId)
{
    *a_pId = 0;
    oe_enclave_t* enclave;
    oe_result_t result = oe_create_enclave(a_TaIdString,
                                           0,
                                           a_Flags,
                                           NULL,
                                           0,
                                           NULL,
                                           0,
                                           &enclave);
    if (result != OE_OK) {
        return Tcps_Bad;
    }
    *a_pId = (sgx_enclave_id_t)enclave;
    return Tcps_Good;
}

Tcps_StatusCode Tcps_CreateTAInternal(
    _In_z_ const char* a_TaIdString,
    _In_ uint32_t a_Flags,
    _Out_ sgx_enclave_id_t* a_pId);

oe_result_t oe_create_enclave(
    _In_z_ const char* path,
    _In_ oe_enclave_type_t type,
    _In_ uint32_t flags,
    _In_reads_bytes_(configSize) const void* config,
    _In_ uint32_t configSize,
    _In_ const oe_ocall_func_t* ocall_table,
    _In_ uint32_t ocall_table_size,
    _Out_ oe_enclave_t** enclave)
{
    *enclave = NULL;

    TCPS_UNUSED(type);
    TCPS_UNUSED(config);
    TCPS_UNUSED(configSize);

    g_ocall_table_v2.nr_ocall = ocall_table_size;
    g_ocall_table_v2.call_addr = (oe_call_t*)ocall_table;

    if (flags & OE_ENCLAVE_FLAG_SERIALIZE_ECALLS) {
        g_serialize_ecalls = TRUE;
        flags &= ~OE_ENCLAVE_FLAG_SERIALIZE_ECALLS;
    } else {
        g_serialize_ecalls = FALSE;
    }

    // Load the enclave.
    sgx_enclave_id_t eid;
    Tcps_StatusCode uStatus = Tcps_CreateTAInternal(path, flags, &eid);
    if (Tcps_IsBad(uStatus)) {
        return OE_FAILURE;
    }

    *enclave = (oe_enclave_t*)eid;
    return OE_OK;
}

oe_result_t oe_call_enclave(oe_enclave_t* enclave, const char* func, void* args)
{
    // This API is deprecated.
    return OE_FAILURE;
}

oe_result_t oe_ecall(oe_enclave_t* enclave, uint16_t func, uint64_t argIn, uint64_t* argOut)
{
    // This API is deprecated.
    return OE_FAILURE;
}

/* TODO: delete this API once callers are updated to call oe_terminate_enclave */
Tcps_StatusCode Tcps_DestroyTA(
    _In_ sgx_enclave_id_t a_Id)
{
    oe_enclave_t* enclave = (oe_enclave_t*)a_Id;
    oe_result_t result = oe_terminate_enclave(enclave);
    return (result != OE_OK) ? Tcps_Bad : Tcps_Good;
}

const char* oe_result_str(_In_ oe_result_t result)
{
    static char message[80];
    sprintf_s(message, sizeof(message), "Error %d", result);
    return message;
}

void* ocall_malloc(_In_ size_t size)
{
    return malloc(size);
}

void* ocall_realloc(_In_ void* ptr, _In_ size_t size)
{
    return realloc(ptr, size);
}

void* ocall_calloc(_In_ size_t nmemb, _In_ size_t size)
{
    return calloc(nmemb, size);
}

void ocall_free(_In_ void* ptr)
{
    free(ptr);
}

void ocall_CopyReeMemoryFromBufferChunk(
    _In_ void* ptr,
    _In_ BufferChunk chunk)
{
    memcpy(ptr, chunk.buffer, chunk.size);
}

oe_result_t oe_get_report_v1(
    _In_ oe_enclave_t* enclave,
    _In_ uint32_t flags,
    _In_reads_opt_(opt_params_size) const void* opt_params,
    _In_ size_t opt_params_size,
    _Out_ uint8_t* report_buffer,
    _Out_ size_t* report_buffer_size)
{
    GetReport_Result result;
    buffer1024 optParamsBuffer;
    sgx_enclave_id_t eid = (sgx_enclave_id_t)enclave;
    COPY_BUFFER(optParamsBuffer, opt_params, opt_params_size);
    sgx_status_t sgxStatus = ecall_get_report(eid, &result, flags, optParamsBuffer, opt_params_size);
    oe_result_t oeResult = GetOEResultFromSgxStatus(sgxStatus);
    if (oeResult == OE_OK) {
        *report_buffer_size = result.report_buffer_size;
        memcpy(report_buffer, result.report_buffer, result.report_buffer_size);
    }
    return oeResult;
}

oe_result_t oe_get_report_v2(
    _In_ oe_enclave_t* enclave,
    _In_ uint32_t flags,
    _In_reads_opt_(opt_params_size) const void* opt_params,
    _In_ size_t opt_params_size,
    _Outptr_ uint8_t** report_buffer,
    _Out_ size_t* report_buffer_size)
{
    GetReport_Result result;
    buffer1024 optParamsBuffer;
    sgx_enclave_id_t eid = (sgx_enclave_id_t)enclave;
    COPY_BUFFER(optParamsBuffer, opt_params, opt_params_size);
    sgx_status_t sgxStatus = ecall_get_report(eid, &result, flags, optParamsBuffer, opt_params_size);
    oe_result_t oeResult = GetOEResultFromSgxStatus(sgxStatus);
    if (oeResult == OE_OK) {
        *report_buffer = malloc(result.report_buffer_size);
        if (*report_buffer == NULL) {
            return OE_OUT_OF_MEMORY;
        }
        *report_buffer_size = result.report_buffer_size;
        memcpy(*report_buffer, result.report_buffer, result.report_buffer_size);
    }
    return oeResult;
}

void oe_free_report(uint8_t* report_buffer)
{
    free(report_buffer);
}

oe_result_t oe_verify_report(
    _In_ oe_enclave_t* enclave,
    _In_reads_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    _Out_opt_ oe_report_t* parsed_report)
{
    buffer1024 reportBuffer;
    oe_result_t oeResult;
    sgx_enclave_id_t eid = (sgx_enclave_id_t)enclave;
    if (parsed_report != NULL) {
        oeResult = oe_parse_report(report, report_size, parsed_report);
        if (oeResult != OE_OK) {
            return oeResult;
        }
    }

    COPY_BUFFER(reportBuffer, report, report_size);
    sgx_status_t sgxStatus = ecall_verify_report(eid, (int*)&oeResult, reportBuffer, report_size);
    if (sgxStatus != SGX_SUCCESS) {
        return GetOEResultFromSgxStatus(sgxStatus);
    }
    return oeResult;
}

callV2_Result ocall_v2(uint32_t func, buffer4096 inBuffer, size_t inBufferSize)
{
    callV2_Result result;

    if (func > g_ocall_table_v2.nr_ocall) {
        result.outBufferSize = 0;
        return result;
    }

    oe_call_t call = g_ocall_table_v2.call_addr[func];
    call(inBuffer.buffer,
        inBufferSize,
        result.outBuffer,
        sizeof(result.outBuffer),
        &result.outBufferSize);

    return result;
}

oe_result_t oe_call_enclave_function( 
    _In_ oe_enclave_t* enclave,
    _In_ uint32_t function_id,
    _In_reads_bytes_(input_buffer_size) void* input_buffer,
    _In_ size_t input_buffer_size,
    _Out_writes_bytes_to_(output_buffer_size, *output_bytes_written) void* output_buffer,
    _In_ size_t output_buffer_size,
    _Out_ size_t* output_bytes_written)
{
    int serialize_ecall = g_serialize_ecalls;

    if (output_buffer_size > 4096) {
        return OE_INVALID_PARAMETER;
    }

    callV2_Result* result = malloc(sizeof(*result));
    if (result == NULL) {
        return OE_OUT_OF_MEMORY;
    }

    sgx_enclave_id_t eid = (sgx_enclave_id_t)enclave;
    buffer4096 inBufferStruct;
    COPY_BUFFER(inBufferStruct, input_buffer, input_buffer_size);

    if (serialize_ecall) {
        oe_acquire_enclave_mutex(enclave);
    }

    sgx_status_t sgxStatus = ecall_v2(eid, result, function_id, inBufferStruct, input_buffer_size);

    if (serialize_ecall) {
        oe_release_enclave_mutex(enclave);
    }

    if (sgxStatus == SGX_SUCCESS) {
        memcpy(output_buffer, result->outBuffer, result->outBufferSize);
        *output_bytes_written = result->outBufferSize;
    }
    oe_result_t oeResult = GetOEResultFromSgxStatus(sgxStatus);
    free(result);
    return oeResult;
}

/**
 * Gets the public key of an enclave.
 *
 * @param[in] enclave The instance of the enclave that will be used.
 * @param[in] seal_policy The seal policy used to determine which key to get.
 * @param[out] key_buffer Upon success, this points to the public key.
 * @param[out] key_buffer_size Upon success, this contains the size of the *key_buffer* buffer.
 * @param[out] key_info Reserved for future use.  Must pass NULL.
 * @param[out] key_info_size Reserved for future use.  Must pass NULL.
 *
 * @retval OE_OK The public key was successfully obtained.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 */
oe_result_t oe_get_public_key_by_policy(
    oe_enclave_t* enclave,
    oe_seal_policy_t seal_policy,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size)
{
    /* TODO: to be implemented */
    return OE_FAILURE;
}

void oe_free_public_key(
    uint8_t* key_buffer,
    uint8_t* key_info)
{
    free(key_buffer);
    free(key_info);
}
