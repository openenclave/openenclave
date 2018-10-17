/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
/* TODO: delete this file, which only contains deprecated APIs */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <tcps_u.h>
#include "TcpsCalls_u.h"

TCPConnect_Result
ocall_TCPConnect(
    buffer256 serverName,
    uint16_t port)
{
    TCPConnect_Result result = { 0 };

    /* Resolve server name. */
    ADDRINFO* ai = NULL;
    char serv[10];
    sprintf_s(serv, sizeof(serv), "%d", port);
    int err = getaddrinfo(serverName.buffer, serv, NULL, &ai);
    if (err != 0) {
        result.status = Tcps_BadCommunicationError;
        return result;
    }

    /* Create socket. */
    SOCKET s = socket(ai->ai_family, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(ai);
        result.status = Tcps_BadCommunicationError;
        return result;
    }

    /* Connect socket. */
    err = connect(s, ai->ai_addr, (int)ai->ai_addrlen);
    freeaddrinfo(ai);
    if (err == SOCKET_ERROR) {
        closesocket(s);
        result.status = Tcps_BadCommunicationError;
        return result;
    }

    result.status = Tcps_Good;
    result.connectionHandle = s;
    return result;
}

TCPSend_Result
ocall_TCPSend(
    uint32_t connectionHandle,
    buffer4096 buffer,
    uint32_t sizeToSend)
{
    TCPSend_Result result = { 0 };
    SOCKET s = (SOCKET)connectionHandle;
    result.sizeSent = send(s, buffer.buffer, sizeToSend, 0);
    if (result.sizeSent == SOCKET_ERROR) {
        result.status = Tcps_BadCommunicationError;
    }
    return result;
}

TCPReceive_Result
ocall_TCPReceive(
    uint32_t connectionHandle,
    uint32_t sizeToReceive)
{
    TCPReceive_Result result = { 0 };
    SOCKET s = (SOCKET)connectionHandle;

    result.sizeReceived = recv(s, result.buffer, sizeToReceive, 0);
    if (result.sizeReceived == SOCKET_ERROR) {
        result.status = Tcps_BadCommunicationError;
    }
    return result;
}

Tcps_StatusCode
ocall_TCPClose(
    uint32_t connectionHandle)
{
    SOCKET s = (SOCKET)connectionHandle;
    int err = closesocket(s);
    return (err == SOCKET_ERROR) ? Tcps_BadCommunicationError : Tcps_Good;
}
