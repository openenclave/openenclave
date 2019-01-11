/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include "oetests_t.h"
#include <openenclave/enclave.h>
#include <string.h>

void ecall_DoNothing()
{
}

oe_result_t ecall_ReturnOk()
{
    return OE_OK;
}

int ecall_PrintString(const char* fmt, const char* arg)
{
    return (int)ocall_PrintString(fmt, arg);
}

int ecall_BufferToInt(int* output, const void* buffer, size_t size)
{
    return (int)ocall_BufferToInt(output, buffer, size);
}

void ecall_CopyInt(const int* input, int* output)
{
    *output = *input;
}

/* This client connects to an echo server, sends a large buffer,
* and verifies that the response matches the input.
*/
oe_result_t ecall_RunClient(_In_z_ const char* server, _In_z_ const char* serv)
{
    oe_result_t uStatus = OE_FAILURE;
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
    int messageLength = 32000;
    message = malloc(messageLength);
    if (message == NULL) {
        uStatus = OE_OUT_OF_MEMORY;
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
        uStatus = OE_OUT_OF_MEMORY;
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

    uStatus = OE_OK;

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

oe_result_t ecall_StartServer(_In_z_ const char* serv)
{
    oe_result_t uStatus = OE_FAILURE;
    struct addrinfo* ai = NULL;
    SOCKET listener = INVALID_SOCKET;

    /* Resolve service name. */
    struct addrinfo hints = { 0 };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    int err = getaddrinfo(NULL, serv, &hints, &ai);
    if (err != 0) {
        return OE_FAILURE;
    }

    /* Create listener socket. */
    listener = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (listener == INVALID_SOCKET) {
        freeaddrinfo(ai);
        return OE_FAILURE;
    }
    if (bind(listener, ai->ai_addr, ai->ai_addrlen) == SOCKET_ERROR) {
        closesocket(listener);
        freeaddrinfo(ai);
        return OE_FAILURE;
    }
    freeaddrinfo(ai);

    if (listen(listener, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listener);
        return OE_FAILURE;
    }
    
    g_TestListener = listener;
    return OE_OK;
}

/* This server acts as an echo server.  It accepts a connection,
* receives messages, and echoes them back.
*/
oe_result_t ecall_FinishServer(void)
{
    oe_result_t uStatus = OE_FAILURE;
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
    uStatus = OE_OK;

Done:
    if (s != INVALID_SOCKET) {
        closesocket(s);
    }
    if (listener != INVALID_SOCKET) {
        closesocket(listener);
    }
    return uStatus;
}
