/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include "oetests_t.h"
#include "sgx_trts.h"
#include <openenclave/enclave.h>
#include <string.h>

void ecall_DoNothing()
{
}

Tcps_StatusCode ecall_ReturnOk()
{
    return Tcps_Good;
}

int ecall_PrintString(char* fmt, char* arg)
{
    return (int)ocall_PrintString(fmt, arg);
}

int ecall_BufferToInt(int* output, void* buffer, size_t size)
{
    return (int)ocall_BufferToInt(output, buffer, size);
}

void ecall_CopyInt(int* input, int* output)
{
    *output = *input;
}

oe_CreateBuffer_Result ecall_CreateReeBufferFromTeeBuffer(_In_ void* hTeeBuffer)
{
    oe_CreateBuffer_Result result = { 0 };
    char* data;
    int size;

    result.uStatus = TcpsGetTeeBuffer(hTeeBuffer, &data, &size);
    if (Tcps_IsBad(result.uStatus)) {
        return result;
    }

    result.uStatus = TcpsPushDataToReeBuffer(data, size, &result.hBuffer);
    return result;
}

/* This client connects to an echo server, sends a large buffer,
* and verifies that the response matches the input.
*/
Tcps_StatusCode ecall_RunClient(char* server, char* serv)
{
    Tcps_StatusCode uStatus = Tcps_BadCommunicationError;
    struct addrinfo* ai = NULL;
    SOCKET s = INVALID_SOCKET;
    char* message = NULL;
    char* reply = NULL;

    /* Resolve server name. */
    struct addrinfo hints = { 0 };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int err = getaddrinfo(server, serv, &hints, &ai);
    if (err != 0) {
        goto Done;
    }

    /* Create connection. */
    s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == INVALID_SOCKET) {
        goto Done;
    }
    if (connect(s, ai->ai_addr, ai->ai_addrlen) == SOCKET_ERROR) {
        goto Done;
    }

    /* Send a large message, prefixed by its size. */
    int messageLength = 8096;
    message = malloc(messageLength);
    if (message == NULL) {
        uStatus = Tcps_BadOutOfMemory;
        goto Done;
    }
    for (int i = 0; i < messageLength; i++) {
        message[i] = (i & 0xFF);
    }
    int netMessageLength = htonl(messageLength);
    int bytesSent = send(s, (char*)&netMessageLength, sizeof(netMessageLength), 0);
    if (bytesSent == SOCKET_ERROR) {
        goto Done;
    }
    bytesSent = send(s, message, messageLength, 0);
    if (bytesSent == SOCKET_ERROR) {
        goto Done;
    }

    /* Receive the reply size. */
    int replyLength;
    int bytesReceived = recv(s, (char*)&replyLength, sizeof(replyLength), MSG_WAITALL);
    if (bytesReceived == SOCKET_ERROR) {
        goto Done;
    }
    replyLength = ntohl(replyLength);
    if (replyLength != messageLength) {
        goto Done;
    }

    /* Receive the reply. */
    reply = malloc(replyLength);
    if (reply == NULL) {
        uStatus = Tcps_BadOutOfMemory;
        goto Done;
    }
    bytesReceived = recv(s, reply, replyLength, MSG_WAITALL);
    if (bytesReceived != bytesSent) {
        goto Done;
    }

    /* Verify that the reply matches the original message. */
    if (memcmp(message, reply, messageLength) != 0) {
        goto Done;
    }

    uStatus = Tcps_Good;

Done:
    free(message);
    free(reply);
    if (s != INVALID_SOCKET) {
        closesocket(s);
    }
    if (ai != NULL) {
        freeaddrinfo(ai);
    }
    return uStatus;
}

SOCKET g_TestListener = INVALID_SOCKET;

Tcps_StatusCode ecall_StartServer(char* serv)
{
    Tcps_StatusCode uStatus = Tcps_BadCommunicationError;
    struct addrinfo* ai = NULL;
    SOCKET listener = INVALID_SOCKET;

    /* Resolve service name. */
    struct addrinfo hints = { 0 };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    int err = getaddrinfo(NULL, serv, &hints, &ai);
    if (err != 0) {
        return Tcps_BadCommunicationError;
    }

    /* Create listener socket. */
    listener = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (listener == INVALID_SOCKET) {
        freeaddrinfo(ai);
        return Tcps_BadCommunicationError;
    }
    if (bind(listener, ai->ai_addr, ai->ai_addrlen) == SOCKET_ERROR) {
        closesocket(listener);
        freeaddrinfo(ai);
        return Tcps_BadCommunicationError;
    }
    freeaddrinfo(ai);

    if (listen(listener, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listener);
        return Tcps_BadCommunicationError;
    }
    
    g_TestListener = listener;
    return Tcps_Good;
}

/* This server acts as an echo server.  It accepts a connection,
* receives messages, and echoes them back.
*/
Tcps_StatusCode ecall_FinishServer(void)
{
    Tcps_StatusCode uStatus = Tcps_BadCommunicationError;
    SOCKET s = INVALID_SOCKET;
    SOCKET listener = g_TestListener;
    g_TestListener = INVALID_SOCKET;

    /* Accept a client connection. */
    struct sockaddr_storage addr;
    int addrlen = sizeof(addr);
    s = accept(listener, (struct sockaddr*)&addr, &addrlen);
    if (s == INVALID_SOCKET) {
        goto Done;
    }

    /* Receive a text message, prefixed by its size. */
    int netMessageLength;
    int messageLength;
    char message[80];
    int bytesReceived = recv(s, (char*)&netMessageLength, sizeof(netMessageLength), MSG_WAITALL);
    if (bytesReceived == SOCKET_ERROR) {
        goto Done;
    }
    messageLength = ntohl(netMessageLength);
    if (messageLength > sizeof(message)) {
        goto Done;
    }
    bytesReceived = recv(s, message, messageLength, MSG_WAITALL);
    if (bytesReceived != messageLength) {
        goto Done;
    }

    /* Send it back to the client, prefixed by its size. */
    int bytesSent = send(s, (char*)&netMessageLength, sizeof(netMessageLength), 0);
    if (bytesSent == SOCKET_ERROR) {
        goto Done;
    }
    bytesSent = send(s, message, messageLength, 0);
    if (bytesSent == SOCKET_ERROR) {
        goto Done;
    }
    uStatus = Tcps_Good;

Done:
    if (s != INVALID_SOCKET) {
        closesocket(s);
    }
    if (listener != INVALID_SOCKET) {
        closesocket(listener);
    }
    return uStatus;
}

Tcps_StatusCode ecall_TestSgxIsWithinEnclave(void* outside, int size)
{
    int result = sgx_is_within_enclave(&result, sizeof(result));
    Tcps_ReturnErrorIfTrue(result == 0, Tcps_Bad);

#ifndef USE_OPTEE
    // TrustZone uses a separate address space and requires marshalling data.
    // As such, there is a (separate) address with the same numeric value,
    // and the following check currently doesn't work.  There's probably
    // some way to differentiate and make this work in the future.
    result = sgx_is_within_enclave(outside, size);
    Tcps_ReturnErrorIfTrue(result != 0, Tcps_Bad);
#endif

    return Tcps_Good;
}

Tcps_StatusCode ecall_TestSgxIsOutsideEnclave(void* outside, int size)
{
    int result = sgx_is_outside_enclave(outside, size);
    Tcps_ReturnErrorIfTrue(result == 0, Tcps_Bad);

#ifndef USE_OPTEE
    // TrustZone uses a separate address space and requires marshalling data.
    // As such, there is a (separate) address with the same numeric value,
    // and the following check currently doesn't work.  There's probably
    // some way to differentiate and make this work in the future.
    result = sgx_is_outside_enclave(&result, sizeof(result));
    Tcps_ReturnErrorIfTrue(result != 0, Tcps_Bad);
#endif

    return Tcps_Good;
}
