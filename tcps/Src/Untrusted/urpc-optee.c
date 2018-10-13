/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <windows.h>
#include <stdint.h>
#include <OpteeCalls.h>
#include <sgx_edger8r.h>
#include <tcps.h>

typedef sgx_status_t (SGX_CDECL * optee_ocall_t)(void* pms);

/* This is actually not a hard limit since we never use it to actually
 * allocate any space.  As long as the caller passes a valid number,
 * the "maximum" is ignored.  It's only used by the debugger.
 */
#define MAX_OCALLS 256

typedef struct {
    size_t nr_ocall;
    optee_ocall_t func_addr[MAX_OCALLS];
} optee_ocall_table_t;

optee_ocall_table_t* g_OpteeOcallTable = NULL;

BOOL /* Returns TRUE on success, FALSE on failure. */
OPTEE_CALL
OpteeRpcCallback(
    _In_opt_                        void *         rpcCallbackContext,
    _In_                            uint32_t       rpcType,
    _In_reads_bytes_(rpcInputSize)  const void *   rpcInputBuffer,
    _In_                            uint32_t       rpcInputSize,
    _Out_writes_bytes_to_(
        rpcOutputSize,
        *rpcOutputSizeWritten)      void *         rpcOutputBuffer,
    _In_                            uint32_t       rpcOutputSize,
    _Out_                           uint32_t *     rpcOutputSizeWritten)
{
    sgx_status_t sgxStatus = SGX_SUCCESS;

    TCPS_UNUSED(rpcCallbackContext);

    if (rpcType >= g_OpteeOcallTable->nr_ocall) {
         /* No such ocalls exist. */
        return FALSE;
    }

    /* OP-TEE passes us the max rpcOutputSize value, not the actual size
     * desired by the caller, so we cannot check for equality.
     */
    if (rpcInputSize > rpcOutputSize) {
        return FALSE;
    }

    /* Copy input buffer to mutable output buffer. */
    memcpy(rpcOutputBuffer, rpcInputBuffer, rpcInputSize);
    *rpcOutputSizeWritten = rpcInputSize;

    sgxStatus = g_OpteeOcallTable->func_addr[rpcType](rpcOutputBuffer);
    
    return (sgxStatus == SGX_SUCCESS);
}

BOOL
CallTrEEService(
    _In_ HANDLE ServiceHandle,
    _In_ ULONG FunctionCode,
    _In_reads_bytes_(InputBufferLength) PVOID InputBufferPtr,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWritten) PVOID OutputBufferPtr,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG BytesWrittenPtr)
{
    ULONG inputBufferSize = InputBufferLength;
    ULONG outputBufferSize = OutputBufferLength;
    PVOID inputBuffer = InputBufferPtr;
    PVOID outputBuffer = OutputBufferPtr;
    char dummyInputBuffer[1];
    char dummyOutputBuffer[1];

    if (inputBuffer == NULL) {
        inputBuffer = dummyInputBuffer;
        inputBufferSize = 1;
    }

    if (outputBuffer == NULL) {
        outputBuffer = dummyOutputBuffer;
        outputBufferSize = 1;
    }

    BOOL isSuccess = CallOpteeCommand(
        ServiceHandle,
        FunctionCode,
        inputBuffer, inputBufferSize,
        outputBuffer, outputBufferSize,
        BytesWrittenPtr,
        OpteeRpcCallback,
        NULL); /* Context to pass to ocall callback. */

    return isSuccess;
}

sgx_status_t sgx_optee_ecall(const sgx_enclave_id_t eid,
                             const int index,
                             const void* ocall_table,
                             void* inOutBuffer,
                             size_t inOutBufferLength)
{
    sgx_status_t sgxStatus = SGX_ERROR_UNEXPECTED;
    ULONG bytesWritten;
    BOOL ret;
    HANDLE serviceHandle = (HANDLE) eid;

    g_OpteeOcallTable = (optee_ocall_table_t*)ocall_table;

    ret = CallTrEEService(serviceHandle,
                          index,
                          inOutBuffer,
                          inOutBufferLength,
                          inOutBuffer,
                          inOutBufferLength,
                          &bytesWritten);

    sgxStatus = (ret) ? SGX_SUCCESS : SGX_ERROR_UNEXPECTED;

    return sgxStatus;
}

#if 0
/* This implementation is a longer-term implementation that directly implements
 * OE over TrustZone.
 */
#include <openenclave/host.h>
oe_result_t oe_call_enclave_function( 
    _In_ oe_enclave_t* enclave,
    _In_ uint32_t function_id,
    _In_reads_bytes_(input_buffer_size) void* input_buffer,
    _In_ size_t input_buffer_size,
    _Out_writes_bytes_to_(output_buffer_size, *output_bytes_written) void* output_buffer,
    _In_ size_t output_buffer_size,
    _Out_ size_t* output_bytes_written)
{
    BOOL ret;
    HANDLE serviceHandle = (HANDLE)enclave;

    g_OpteeOcallTable = (optee_ocall_table_t*)ocall_table;

    ret = CallTrEEService(serviceHandle,
                          func,
                          input_buffer,
                          input_buffer_size,
                          output_buffer,
                          output_buffer_size,
                          output_bytes_written);

    return (ret) ? OE_OK : OE_UNEXPECTED;
}
#endif
