/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdio.h>
#include <time.h>
#include <windows.h> // for LARGE_INTEGER

#include <tcps.h>

#include "tcps_u.h"
#include "TcpsCalls_u.h"
#include "buffer.h"

#define MIN(a,b) (((a) < b) ? (a) : (b))

typedef unsigned __int64 uint64_t;
typedef unsigned __int32 uint32_t;

/* Time-related APIs */

QueryPerformanceCounter_Result ocall_QueryPerformanceCounter(void)
{
    QueryPerformanceCounter_Result result;

    if (!QueryPerformanceCounter((LARGE_INTEGER*)&result.count)) {
        result.status = Tcps_Bad;
    } else {
        result.status = Tcps_Good;
    }

    return result;
}

unsigned int ocall_GetTickCount(void)
{
    return GetTickCount();
}

uint64_t ocall_time64(void)
{
    uint64_t t;
    _time64((__time64_t*)&t);
    return t;
}

GetTm_Result ocall_localtime64(uint64_t timer)
{
    GetTm_Result result;
    result.err = _localtime64_s((struct tm*)&result.tm, (const __time64_t*)&timer);
    return result;
}

GetTm_Result ocall_gmtime64(uint64_t timer)
{
    GetTm_Result result;
    result.err = _gmtime64_s((struct tm*)&result.tm, (const __time64_t*)&timer);
    return result;
}

/* Process/thread-related APIs */

Tcps_StatusCode ocall_exit(int result)
{
    _exit(result);
    return Tcps_Good;
}

/* I/O related APIs */

Tcps_StatusCode ocall_puts(buffer1024 str, int bNewline)
{
    uint32_t error;

    if (bNewline) {
        error = (puts(str.buffer) >= 0);
    } else {
        error = (fputs(str.buffer, stdout) >= 0);
    }

    if (error) {
        return Tcps_Bad;
    }

    return Tcps_Good;
}

/* We currently use a global mutex.  In the future, this should
 * be changed to a per-TA mutex.
 */
int g_GlobalMutexInitialized = 0;
CRITICAL_SECTION g_GlobalMutex;

Tcps_StatusCode TcpsAcquireTAMutex(_In_ sgx_enclave_id_t eid)
{
    Tcps_StatusCode uStatus = Tcps_Good;

    TCPS_UNUSED(eid);

    if (!g_GlobalMutexInitialized) {
        InitializeCriticalSection(&g_GlobalMutex);
        g_GlobalMutexInitialized++;
    }
    //printf("+ecall: %x\n", GetCurrentThreadId());
    
    for(;;) {
        if (TryEnterCriticalSection(&g_GlobalMutex)) {
            /* Mutex acquired successfully */
            break;
        }

        /* Check if another thread requested this thread to terminate. */
        if (Tcps_P_Thread_WasTerminationRequested()) {
            Tcps_Trace(
                Tcps_TraceLevelWarning,
                "%s: abandoning!\n", 
                __FUNCTION__);
            uStatus = Tcps_BadOperationAbandoned;
            break;
        }

        Sleep(100);
    }

    return uStatus;
}

Tcps_Void TcpsReleaseTAMutex(_In_ sgx_enclave_id_t eid)
{
    TCPS_UNUSED(eid);
    LeaveCriticalSection(&g_GlobalMutex);
    //printf("-ecall: %x\n", GetCurrentThreadId());
}

/* Send a buffer into the TEE, one chunk at a time if needed. */
Tcps_StatusCode
TcpsPushDataToTeeBuffer(
    _In_ sgx_enclave_id_t eid,
    _In_reads_(a_BufferSize) uint8_t* a_Buffer,
    _In_ size_t a_BufferSize,
    _Out_ void** a_phTeeBuffer)
{
    size_t bytesCopied = 0;
    void* hTeeBuffer = NULL;
    sgx_status_t sgxStatus = SGX_SUCCESS;
    BufferChunk chunk;
    CreateBuffer_Result result;

Tcps_InitializeStatus(Tcps_Module_Helper_u, "TcpsPushDataToTeeBuffer"); 

    while (bytesCopied < a_BufferSize) {
        int bytesRemaining = a_BufferSize - bytesCopied;
        chunk.size = MIN(sizeof(chunk.buffer), bytesRemaining);

        COPY_BUFFER(chunk, a_Buffer + bytesCopied, chunk.size);

        if (hTeeBuffer == NULL) {
            sgxStatus = ecall_CreateTeeBuffer(eid, &result, chunk);
            Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, Tcps_Bad);
            uStatus = result.uStatus;
            hTeeBuffer = result.hBuffer;
        } else {
            sgxStatus = ecall_AppendToTeeBuffer(eid, &uStatus, hTeeBuffer, chunk);
            Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, Tcps_Bad);
        }
        Tcps_GotoErrorIfBad(uStatus);

        bytesCopied += chunk.size;
    }

    *a_phTeeBuffer = hTeeBuffer;

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;

    if (hTeeBuffer != NULL) {
        (void)ecall_FreeTeeBuffer(eid, hTeeBuffer);
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

Tcps_StatusCode TcpsGetReeBuffer(
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

CreateBuffer_Result ocall_CreateReeBuffer(BufferChunk chunk)
{
    CreateBuffer_Result result = {0};
    if (chunk.size > sizeof(chunk.buffer)) {
        result.uStatus = Tcps_BadInvalidArgument;
        return result;
    }
    InternalBuffer_t* buffer = CreateInternalBuffer(chunk.size);
    if (buffer == NULL) {
        result.uStatus = Tcps_BadOutOfMemory;
    } else {
        memcpy(buffer->ptr, chunk.buffer, buffer->size);
        result.hBuffer = buffer->handle;
    }
    return result;
}

Tcps_StatusCode ocall_AppendToReeBuffer(void* a_hReeBuffer, BufferChunk a_Chunk)
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
        result.uStatus = Tcps_Bad;
        return result;
    }

    int bytesLeft = buffer->size - a_Offset;
    if (bytesLeft < 1) {
        result.uStatus = Tcps_BadInvalidArgument;
        return result;
    }

    int chunkSize = MIN(sizeof(result.buffer), bytesLeft);
    result.size = chunkSize;
    memcpy(result.buffer, buffer->ptr + a_Offset, chunkSize);

    return result;
}
