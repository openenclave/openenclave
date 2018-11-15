/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <openenclave/enclave.h>
#include <tcps_string_t.h>
#include "oeoverintelsgx_t.h"
#include "tcps.h"
#include "buffer.h"
#include "TcpsTls.h"

oe_result_t
TcpsPushDataToReeBuffer(
    _In_reads_bytes_(a_BufferSize) const uint8_t* a_Buffer,
    _In_ size_t a_BufferSize,
    _Out_ void** a_phReeBuffer)
{
    size_t bytesCopied = 0;
    void* hReeBuffer = NULL;
    sgx_status_t sgxStatus = SGX_SUCCESS;
    oe_BufferChunk chunk;
    CreateBuffer_Result result;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "TcpsPushDataToReeBuffer"); 

    while (bytesCopied < a_BufferSize) {
        int bytesRemaining = a_BufferSize - bytesCopied;
        chunk.size = MIN(sizeof(chunk.buffer), bytesRemaining);

        COPY_BUFFER(chunk, a_Buffer + bytesCopied, chunk.size);

        if (hReeBuffer == NULL) {
            sgxStatus = ocall_CreateReeBuffer(&result, chunk);
            Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, OE_FAILURE);
            uStatus = result.uStatus;
            hReeBuffer = result.hBuffer;
        } else {
            sgxStatus = ocall_AppendToReeBuffer(&uStatus, hReeBuffer, chunk);
            Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, OE_FAILURE);
        }
        Tcps_GotoErrorIfBad(uStatus);

        bytesCopied += chunk.size;
    }

    *a_phReeBuffer = hReeBuffer;

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;

    if (hReeBuffer != NULL) {
        TcpsFreeReeBuffer(hReeBuffer);
    }

Tcps_FinishErrorHandling;
}

oe_result_t
TcpsPullDataFromReeBuffer(
    _In_ void* a_hReeBuffer,
    _Out_writes_bytes_all_(a_BufferSize) uint8_t* a_Buffer,
    _In_ size_t a_BufferSize)
{
    size_t bytesCopied = 0;
    sgx_status_t sgxStatus = SGX_SUCCESS;
    oe_BufferChunk chunk;
    GetChunk_Result result;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "TcpsPullDataFromReeBuffer"); 

    while (bytesCopied < a_BufferSize) {
        int bytesRemaining = a_BufferSize - bytesCopied;
        chunk.size = MIN(sizeof(chunk.buffer), bytesRemaining);

        sgxStatus = ocall_GetReeBufferChunk(&result, a_hReeBuffer, (int)bytesCopied);
        Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, OE_FAILURE);
        Tcps_GotoErrorIfBad(result.uStatus);
        Tcps_GotoErrorIfTrue(chunk.size != result.size, OE_FAILURE);

        memcpy(a_Buffer + bytesCopied, result.buffer, result.size);
        bytesCopied += chunk.size;
    }

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
Tcps_FinishErrorHandling;
}

void TcpsFreeReeBuffer(_In_ void* a_hReeBuffer)
{
    (void)ocall_FreeReeBuffer(a_hReeBuffer);
}

CreateBuffer_Result ecall_CreateTeeBuffer(
    _In_ oe_BufferChunk chunk)
{
    CreateBuffer_Result result = { 0 };
    InternalBuffer_t* buffer = CreateInternalBuffer(chunk.size);
    if (buffer == NULL) {
        result.uStatus = OE_OUT_OF_MEMORY;
    } else {
        memcpy(buffer->ptr, chunk.buffer, buffer->size);
        result.hBuffer = buffer->handle;
    }
    return result;
}

oe_result_t TcpsGetTeeBuffer(
    _In_ void* a_hTeeBuffer,
    _Outptr_ char** a_pBuffer,
    _Out_ int* a_BufferSize)
{
    return GetBuffer(a_hTeeBuffer, a_pBuffer, a_BufferSize);
}

oe_result_t ecall_AppendToTeeBuffer(
    _In_ void* a_hTeeBuffer,
    _In_ oe_BufferChunk a_Chunk)
{
    return AppendToBuffer(a_hTeeBuffer, &a_Chunk);
}

void ecall_FreeTeeBuffer(_In_ void* a_hTeeBuffer)
{
    FreeBuffer(a_hTeeBuffer);
}
