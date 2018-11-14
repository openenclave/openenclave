/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdio.h>
#include <stddef.h>

#ifdef LINUX
#include "sal_unsup.h"
#endif

#include <openenclave/host.h>
#include "oeoverintelsgx_u.h"
#include "../buffer.h"
extern int g_serialize_ecalls;

#define MIN(a,b) (((a) < b) ? (a) : (b))

/* I/O related APIs */

oe_result_t ocall_puts(oe_buffer1024 str, int bNewline)
{
    uint32_t error;

    if (bNewline) {
        error = (puts(str.buffer) >= 0);
    } else {
        error = (fputs(str.buffer, stdout) >= 0);
    }

    if (error) {
        return OE_FAILURE;
    }

    return OE_OK;
}

/* Send a buffer into the TEE, one chunk at a time if needed. */
oe_result_t
TcpsPushDataToTeeBuffer(
    _In_ sgx_enclave_id_t eid,
    _In_reads_(a_BufferSize) uint8_t* a_Buffer,
    _In_ size_t a_BufferSize,
    _Out_ void** a_phTeeBuffer)
{
    size_t bytesCopied = 0;
    void* hTeeBuffer = NULL;
    sgx_status_t sgxStatus = SGX_SUCCESS;
    oe_BufferChunk chunk;
    CreateBuffer_Result result;
    int serialize_ecall = g_serialize_ecalls;

Tcps_InitializeStatus(Tcps_Module_Helper_u, "TcpsPushDataToTeeBuffer"); 

    while (bytesCopied < a_BufferSize) {
        size_t bytesRemaining = a_BufferSize - bytesCopied;
        chunk.size = (int)MIN(sizeof(chunk.buffer), bytesRemaining);

        COPY_BUFFER(chunk, a_Buffer + bytesCopied, chunk.size);

        if (hTeeBuffer == NULL) {
            if (serialize_ecall) {
                oe_acquire_enclave_mutex((oe_enclave_t*)eid);
            }
            sgxStatus = ecall_CreateTeeBuffer(eid, &result, chunk);
            if (serialize_ecall) {
                oe_release_enclave_mutex((oe_enclave_t*)eid);
            }

            Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, OE_FAILURE);
            uStatus = result.uStatus;
            hTeeBuffer = result.hBuffer;
        } else {
            if (serialize_ecall) {
                oe_acquire_enclave_mutex((oe_enclave_t*)eid);
            }
            sgxStatus = ecall_AppendToTeeBuffer(eid, &uStatus, hTeeBuffer, chunk);
            if (serialize_ecall) {
                oe_release_enclave_mutex((oe_enclave_t*)eid);
            }

            Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, OE_FAILURE);
        }
        Tcps_GotoErrorIfBad(uStatus);

        bytesCopied += chunk.size;
    }

    *a_phTeeBuffer = hTeeBuffer;

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;

    if (hTeeBuffer != NULL) {
        if (serialize_ecall) {
            oe_acquire_enclave_mutex((oe_enclave_t*)eid);
        }
        (void)ecall_FreeTeeBuffer(eid, hTeeBuffer);
        if (serialize_ecall) {
            oe_release_enclave_mutex((oe_enclave_t*)eid);
        }
    }
    *a_phTeeBuffer = NULL;

Tcps_FinishErrorHandling;
}

void* TcpsCreateReeBuffer(_In_ int a_BufferSize)
{
    InternalBuffer_t* buffer = CreateInternalBuffer(a_BufferSize);
    if (buffer == NULL) {
        return NULL;
    } else {
        return buffer->handle;
    }
}

oe_result_t TcpsGetReeBuffer(
    _In_ void* a_hReeBuffer,
    _Outptr_ char** a_pBuffer,
    _Out_ int* a_BufferSize)
{
    return GetBuffer(a_hReeBuffer, a_pBuffer, a_BufferSize);
}

void TcpsFreeReeBuffer(_In_ void* a_hReeBuffer)
{
    FreeBuffer(a_hReeBuffer);
}

CreateBuffer_Result ocall_CreateReeBuffer(oe_BufferChunk chunk)
{
    CreateBuffer_Result result = {0};
    if (chunk.size > sizeof(chunk.buffer)) {
        result.uStatus = OE_INVALID_PARAMETER;
        return result;
    }
    InternalBuffer_t* buffer = CreateInternalBuffer(chunk.size);
    if (buffer == NULL) {
        result.uStatus = OE_OUT_OF_MEMORY;
    } else {
        memcpy(buffer->ptr, chunk.buffer, buffer->size);
        result.hBuffer = buffer->handle;
    }
    return result;
}

oe_result_t ocall_AppendToReeBuffer(void* a_hReeBuffer, oe_BufferChunk a_Chunk)
{
    return AppendToBuffer(a_hReeBuffer, &a_Chunk);
}

void ocall_FreeReeBuffer(void* a_hReeBuffer)
{
    FreeBuffer(a_hReeBuffer);
}

GetChunk_Result ocall_GetReeBufferChunk(void* a_hReeBuffer, int a_Offset)
{
    GetChunk_Result result = {0};
    InternalBuffer_t* buffer = FindInternalBufferByHandle(a_hReeBuffer);
    if (buffer == NULL) {
        result.uStatus = OE_FAILURE;
        return result;
    }

    int bytesLeft = buffer->size - a_Offset;
    if (bytesLeft < 1) {
        result.uStatus = OE_INVALID_PARAMETER;
        return result;
    }

    int chunkSize = MIN(sizeof(result.buffer), bytesLeft);
    result.size = chunkSize;
    memcpy(result.buffer, buffer->ptr + a_Offset, chunkSize);

    return result;
}
