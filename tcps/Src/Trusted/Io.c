/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <tcps_socket_t.h>
#include <tcps_string_t.h>
#include "TcpsCalls_t.h"
#include "tcps.h"
#include "buffer.h"

TRANSPORT_CALLBACKS g_TransportClientCallbacks = {
    ClientConnectTransport,
    SendDataOverTransport,
    ReceiveDataOverTransport,
    ClientDisconnectTransport
};

int 
ClientConnectTransport(
    _In_z_ const char* HostName, 
    _In_ unsigned short ServiceName, 
    _In_ unsigned int Timeout, 
    _Outptr_ void** Context)
/*++

Routine Description:

    NOP for SGX since the outside (untrusted) components
    should have already established a TCP connection

Parameters:

    HostName - not used

    ServiceName - not used

    Timeout - not used

    Context - not used

--*/
{
    sgx_status_t sgxStatus;
    buffer256 hostNameBuffer;
    TCPConnect_Result result;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "ClientConnectTransport");

    TCPS_UNUSED(Timeout);

    COPY_BUFFER_FROM_STRING(hostNameBuffer, HostName);

    sgxStatus = ocall_TCPConnect(
        &result,
        hostNameBuffer,
        ServiceName);
    uStatus = result.status;
    Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, Tcps_BadCommunicationError);
    Tcps_GotoErrorIfBad(uStatus);

    Tcps_Trace(
        Tcps_TraceLevelDebug, 
        "ClientConnectTransport: handle = %u\n", 
        connectionHandle);
    *Context = (void *)result.connectionHandle;
    
    return Tcps_Good;

Tcps_BeginErrorHandling;

    return Tcps_BadCommunicationError;
}

int 
SendDataOverTransport(
    const uint8_t* Buffer, 
    unsigned int Size, 
    unsigned int Timeout, 
    unsigned int* Sent, 
    void* Context)
/*++

Routine Description:

    Sends data using an untrusted ocall. Besides the initial handshake,
    application data in the buffer is always encrypted at this point 
    so the outside world will not be able to inspect it

Parameters:

    Buffer - Encrypted buffer to send over the outside connection

    Size - Bytes to send

    Timeout - TODO: not used at the moment

    Sent - Number of bytes that were actually sent

    Context - Contains the ClientID that maps to socket in the outside world

--*/
{
    uint32_t connectionHandle;
    sgx_status_t sgxStatus;
    Tcps_StatusCode tcpsStatus = Tcps_Good;
    TCPSend_Result result;
    buffer4096* message = NULL;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "SendDataOverTransport");

    TCPS_UNUSED(Timeout);

    if ((Size == 0) ||
        (Sent == NULL) ||
        (Buffer == NULL) || 
        (Context == NULL))
    {
#ifdef USE_OPTEE
        EMSG("invalid parameter: Size %#x, Sent %p, Buffer = %p, Context = %p",
            Size, (void*)Sent, Buffer, Context);
#endif
        tcpsStatus = Tcps_BadInvalidArgument;
        Tcps_GotoErrorWithStatus(Tcps_Bad);
    }

    *Sent = 0;

    connectionHandle = (uint32_t)Context;

    Tcps_GotoErrorIfTrue(Size > sizeof(*message), Tcps_BadRequestTooLarge);

    message = (buffer4096*)malloc(sizeof(*message));
    Tcps_GotoErrorIfAllocFailed(message);

    COPY_BUFFER(*message, Buffer, Size);

    sgxStatus = ocall_TCPSend(
        &result,
        connectionHandle,
        *message,
        Size); 

    free(message);

    uStatus = result.status;
    *Sent = result.sizeSent;

    Tcps_Trace(
        Tcps_TraceLevelDebug, 
        "SendDataOverTransport: size = %#x, size sent = %#x, Tcps status = %#x\n", 
        Size,
        *Sent,
        uStatus);

    Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, Tcps_BadCommunicationError);
    Tcps_GotoErrorIfBad(uStatus);

    return Tcps_Good;

Tcps_BeginErrorHandling;

    if (tcpsStatus == Tcps_Good)
    {
        tcpsStatus = Tcps_BadCommunicationError;
    }
    return tcpsStatus;
}

int 
ReceiveDataOverTransport(
    uint8_t* Buffer, 
    unsigned int Size, 
    unsigned int Timeout, 
    unsigned int* Recvd, 
    void* Context)
/*++

Routine Description:

    Receives data using an untrusted ocall. Besides the initial handshake,
    application data in the buffer is still encrypted at this point 
    so the outside world will not be able to inspect it

Parameters:

    Buffer - Buffer to receive data from the outside connection

    Size - Bytes to read

    Timeout - TODO: not used at the moment

    Recvd - Number of bytes that were actually read

    Context - Contains the ClientID that maps to socket in the outside world

--*/
{
    uint32_t connectionHandle;
    sgx_status_t sgxStatus;
    Tcps_StatusCode tcpsStatus = Tcps_Good;
    TCPReceive_Result result;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "ReceiveDataOverTransport");

    TCPS_UNUSED(Timeout);

    if ((Size == 0) ||
        (Recvd == NULL) ||
        (Buffer == NULL) || 
        (Context == NULL))
    {
#ifdef USE_OPTEE
        EMSG("invalid parameter: Size %#x, Recvd %p, Buffer = %p, Context = %p",
            Size, (void*)Recvd, Buffer, Context);
#endif
        tcpsStatus = Tcps_BadInvalidArgument;
        Tcps_GotoErrorWithStatus(Tcps_Bad);
    }

    *Recvd = 0;

    connectionHandle = (uint32_t) Context;

    sgxStatus = ocall_TCPReceive(
        &result,
        connectionHandle,
        Size);
    Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, Tcps_BadCommunicationError);

    uStatus = result.status;
    Tcps_GotoErrorIfTrue(result.sizeReceived > Size, Tcps_BadCommunicationError);

    *Recvd = result.sizeReceived;
    Tcps_Trace(
        Tcps_TraceLevelDebug,
        "ReceiveDataOverTransport: size = %#x, size received = %#x, Tcps status = %#x\n", 
        Size,
        *Recvd,
        uStatus);

    Tcps_GotoErrorIfBad(uStatus);

    memcpy(Buffer, result.buffer, result.sizeReceived);

    return Tcps_Good;

Tcps_BeginErrorHandling;

    if (tcpsStatus == Tcps_Good)
    {
        tcpsStatus = Tcps_BadTimeout;
    }
    return tcpsStatus;
}

void 
ClientDisconnectTransport(
    void** Context)
/*++

Routine Description:

    NOP for SGX since the outside (untrusted) components
    takes care of closing the TCP connection

Parameters:

    Context - not used

--*/
{
    uint32_t connectionHandle;
    sgx_status_t sgxStatus;
    unsigned int retval;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "DisconnectTransport");

    Tcps_GotoErrorIfNull(Context, Tcps_Bad);

    connectionHandle = (uint32_t) *Context;
    Tcps_Trace(
        Tcps_TraceLevelDebug,
        "DisconnectTransport: handle = %u\n", 
        connectionHandle);

    sgxStatus = ocall_TCPClose(
        &retval,
        connectionHandle);
    uStatus = retval;
    Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, Tcps_BadCommunicationError);
    Tcps_GotoErrorIfBad(uStatus);

Tcps_BeginErrorHandling;
}

Tcps_StatusCode
TcpsPushDataToReeBuffer(
    _In_reads_bytes_(a_BufferSize) const uint8_t* a_Buffer,
    _In_ size_t a_BufferSize,
    _Out_ void** a_phReeBuffer)
{
    size_t bytesCopied = 0;
    void* hReeBuffer = NULL;
    sgx_status_t sgxStatus = SGX_SUCCESS;
    BufferChunk chunk;
    CreateBuffer_Result result;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "TcpsPushDataToReeBuffer"); 

    while (bytesCopied < a_BufferSize) {
        int bytesRemaining = a_BufferSize - bytesCopied;
        chunk.size = MIN(sizeof(chunk.buffer), bytesRemaining);

        COPY_BUFFER(chunk, a_Buffer + bytesCopied, chunk.size);

        if (hReeBuffer == NULL) {
            sgxStatus = ocall_CreateReeBuffer(&result, chunk);
            Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, Tcps_Bad);
            uStatus = result.uStatus;
            hReeBuffer = result.hBuffer;
        } else {
            sgxStatus = ocall_AppendToReeBuffer(&uStatus, hReeBuffer, chunk);
            Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, Tcps_Bad);
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

Tcps_StatusCode
TcpsPullDataFromReeBuffer(
    _In_ void* a_hReeBuffer,
    _Out_writes_bytes_all_(a_BufferSize) uint8_t* a_Buffer,
    _In_ size_t a_BufferSize)
{
    size_t bytesCopied = 0;
    sgx_status_t sgxStatus = SGX_SUCCESS;
    BufferChunk chunk;
    GetChunk_Result result;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "TcpsPullDataFromReeBuffer"); 

    while (bytesCopied < a_BufferSize) {
        int bytesRemaining = a_BufferSize - bytesCopied;
        chunk.size = MIN(sizeof(chunk.buffer), bytesRemaining);

        sgxStatus = ocall_GetReeBufferChunk(&result, a_hReeBuffer, (int)bytesCopied);
        Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, Tcps_BadInternalError);
        Tcps_GotoErrorIfBad(result.uStatus);
        Tcps_GotoErrorIfTrue(chunk.size != result.size, Tcps_BadInternalError);

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
    _In_ BufferChunk chunk)
{
    CreateBuffer_Result result = { 0 };
    InternalBuffer_t* buffer = CreateInternalBuffer(chunk.size);
    if (buffer == NULL) {
        result.uStatus = Tcps_BadOutOfMemory;
    } else {
        memcpy(buffer->ptr, chunk.buffer, buffer->size);
        result.hBuffer = buffer->handle;
    }
    return result;
}

Tcps_StatusCode TcpsGetTeeBuffer(
    _In_ void* a_hTeeBuffer,
    _Outptr_ char** a_pBuffer,
    _Out_ int* a_BufferSize)
{
    return GetBuffer(a_hTeeBuffer, a_pBuffer, a_BufferSize);
}

Tcps_StatusCode ecall_AppendToTeeBuffer(
    _In_ void* a_hTeeBuffer,
    _In_ BufferChunk a_Chunk)
{
    return AppendToBuffer(a_hTeeBuffer, &a_Chunk);
}

void ecall_FreeTeeBuffer(_In_ void* a_hTeeBuffer)
{
    FreeBuffer(a_hTeeBuffer);
}
