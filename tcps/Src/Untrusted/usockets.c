/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <tcps_u.h>
#include "TcpsCalls_u.h"
#include "buffer.h"

Tcps_SocketError ocall_WSAStartup(void)
{
    WSADATA wsaData;
    int apiResult = WSAStartup(0x202, &wsaData);
    return (Tcps_SocketError)apiResult;
}

int ocall_WSACleanup(void)
{
    return WSACleanup();
}

gethostname_Result ocall_gethostname(void)
{
    gethostname_Result result;
    int err = gethostname(result.name, sizeof(result.name));
    result.error = (err != 0) ? (Tcps_SocketError)WSAGetLastError() : 0;
    return result;
}

socket_Result ocall_socket(
    Tcps_SocketAddressFamily a_AddressFamily,
    Tcps_SocketType a_Type,
    int a_Protocol)
{
    socket_Result result = { 0 };
    SOCKET s = socket(a_AddressFamily, a_Type, a_Protocol);
    result.hSocket = (void*)s;
    result.error = (s == INVALID_SOCKET) ? (Tcps_SocketError)WSAGetLastError() : 0;
    return result;
}

Tcps_SocketError ocall_listen(void* a_hSocket, int a_nMaxConnections)
{
    SOCKET s = (SOCKET)a_hSocket;
    int err = listen(s, a_nMaxConnections);
    return (err == SOCKET_ERROR) ? (Tcps_SocketError)WSAGetLastError() : 0;
}

GetSockName_Result ocall_getsockname(void* a_hSocket, int a_nNameLen)
{
    GetSockName_Result result = { 0 };
    SOCKET s = (SOCKET)a_hSocket;
    result.addrlen = a_nNameLen;
    int err = getsockname(s, (SOCKADDR*)result.addr, &result.addrlen);
    result.error = (err == SOCKET_ERROR) ? (Tcps_SocketError)WSAGetLastError() : 0;
    return result;
}

GetSockName_Result ocall_getpeername(void* a_hSocket, int a_nNameLen)
{
    GetSockName_Result result = { 0 };
    SOCKET s = (SOCKET)a_hSocket;
    result.addrlen = a_nNameLen;
    int err = getpeername(s, (SOCKADDR*)result.addr, &result.addrlen);
    result.error = (err == SOCKET_ERROR) ? (Tcps_SocketError)WSAGetLastError() : 0;
    return result;
}

send_Result ocall_send(void* a_hSocket, void* a_hReeMessage, int a_Flags)
{
    send_Result result = { 0 };
    SOCKET s = (SOCKET)a_hSocket;
    char* ptr = NULL;
    int size = 0;
    Tcps_StatusCode uStatus = GetBuffer(a_hReeMessage, &ptr, &size);
    if (Tcps_IsBad(uStatus)) {
        result.error = WSAEFAULT;
        return result;
    }
    result.bytesSent = send(s, ptr, size, a_Flags);
    if (result.bytesSent == SOCKET_ERROR) {
        result.error = (Tcps_SocketError)WSAGetLastError();
    }
    return result;
}

recv_Result ocall_recv(void* a_hSocket, int a_nBufferSize, int a_Flags)
{
    recv_Result result = { 0 };
    SOCKET s = (SOCKET)a_hSocket;
    void* hBuffer = CreateBuffer(a_nBufferSize);
    if (hBuffer == NULL) {
        result.error = WSAENOBUFS;
        return result;
    }
    char* ptr = NULL;
    int size = 0;
    Tcps_StatusCode uStatus = GetBuffer(hBuffer, &ptr, &size);
    /* TODO: handle uStatus failure */
    result.bytesReceived = recv(s, ptr, size, a_Flags);
    if (result.bytesReceived == SOCKET_ERROR) {
        result.error = (Tcps_SocketError)WSAGetLastError();
        FreeBuffer(hBuffer);
    } else {
        result.hMessage = hBuffer;
    }
    return result;
}

getaddrinfo_Result ocall_getaddrinfo(
    buffer256 a_NodeName,
    buffer256 a_ServiceName,
    int a_Flags,
    int a_Family,
    int a_SockType,
    int a_Protocol)
{
    getaddrinfo_Result result = { 0 };
    ADDRINFO* ailist = NULL;
    ADDRINFO* ai;
    char* pNodeName = (a_NodeName.buffer[0] != 0) ? a_NodeName.buffer : NULL;
    char* pServiceName = (a_ServiceName.buffer[0] != 0) ? a_ServiceName.buffer : NULL;
    ADDRINFO hints = { 0 };
    void* hBuffer = NULL;

    hints.ai_flags = a_Flags;
    hints.ai_family = a_Family;
    hints.ai_socktype = a_SockType;
    hints.ai_protocol = a_Protocol;

    result.error = getaddrinfo(pNodeName, pServiceName, &hints, &ailist);
    if (ailist == NULL) {
        return result;
    }

    /* Count number of addresses. */
    for (ai = ailist; ai != NULL; ai = ai->ai_next) {
        result.addressCount++;
    }

    hBuffer = CreateBuffer(result.addressCount * sizeof(struct addrinfo_Buffer));
    if (hBuffer == NULL) {
        freeaddrinfo(ailist);
        result.error = WSAENOBUFS;
        return result;
    }

    /* Serialize ailist. */
    addrinfo_Buffer* aibuffer = NULL;
    int size = 0;
    Tcps_StatusCode uStatus = GetBuffer(hBuffer, (char**)&aibuffer, &size);
    /* TODO: handle uStatus failure */
    int i;
    for (i = 0, ai = ailist; ai != NULL; ai = ai->ai_next, i++) {
        addrinfo_Buffer* aib = &aibuffer[i];
        aib->ai_flags = ai->ai_flags; 
        aib->ai_family = ai->ai_family; 
        aib->ai_socktype = ai->ai_socktype; 
        aib->ai_protocol = ai->ai_protocol; 
        aib->ai_addrlen = ai->ai_addrlen; 
        COPY_BUFFER_FROM_STRING(aib->ai_canonname, (ai->ai_canonname != NULL) ? ai->ai_canonname : "");
        COPY_BUFFER(aib->ai_addr, ai->ai_addr, ai->ai_addrlen);
    }

    result.hMessage = hBuffer;
    return result;
}

getsockopt_Result ocall_getsockopt(
    void* a_hSocket,
    int a_nLevel,
    int a_nOptName,
    int a_nOptLen)
{
    getsockopt_Result result = { 0 };
    SOCKET s = (SOCKET)a_hSocket;
    result.len = a_nOptLen;
    int err = getsockopt(s, a_nLevel, a_nOptName, result.buffer, &result.len);
    result.error = (err == SOCKET_ERROR) ? (Tcps_SocketError)WSAGetLastError() : 0;
    return result;
}

Tcps_SocketError ocall_setsockopt(
    void* a_hSocket,
    int a_nLevel,
    int a_nOptName,
    buffer256 a_OptVal,
    int a_nOptLen)
{
    SOCKET s = (SOCKET)a_hSocket;
    int err = setsockopt(s, a_nLevel, a_nOptName, a_OptVal.buffer, a_nOptLen);
    return (err == SOCKET_ERROR) ? (Tcps_SocketError)WSAGetLastError() : 0;
}

ioctlsocket_Result ocall_ioctlsocket(
    void* a_hSocket,
    int a_nCommand,
    unsigned int a_uInputValue)
{
    ioctlsocket_Result result = { 0 };
    SOCKET s = (SOCKET)a_hSocket;
    result.outputValue = a_uInputValue;
    int err = ioctlsocket(s, a_nCommand, &result.outputValue);
    result.error = (err == SOCKET_ERROR) ? (Tcps_SocketError)WSAGetLastError() : 0;
    return result;
}

static void
CopyOutputFds(
    _Out_ Tcps_FdSet* dest,
    _In_ const fd_set* src)
{
    unsigned int i;
    dest->count = src->fd_count;
    for (i = 0; i < src->fd_count; i++) {
        dest->fdArray[i] = (void*)src->fd_array[i];
    }
    for (; i < FD_SETSIZE; i++) {
        dest->fdArray[i] = NULL;
    }
}

static void
CopyInputFds(
    _Out_ fd_set* dest,
    _In_ const Tcps_FdSet* src)
{
    unsigned int i;
    FD_ZERO(dest);
    dest->fd_count = src->count;
    for (i = 0; i < src->count; i++) {
        (void*)dest->fd_array[i] = src->fdArray[i];
    }
}

select_Result ocall_select(
    int a_nFds,
    Tcps_FdSet a_ReadFds,
    Tcps_FdSet a_WriteFds,
    Tcps_FdSet a_ExceptFds,
    Tcps_Timeval a_Timeout)
{
    select_Result result = { 0 };
    fd_set readfds;
    fd_set writefds;
    fd_set exceptfds;
    CopyInputFds(&readfds, &a_ReadFds);
    CopyInputFds(&writefds, &a_WriteFds);
    CopyInputFds(&exceptfds, &a_ExceptFds);
    result.socketsSet = select(a_nFds, &readfds, &writefds, &exceptfds, (struct timeval*)&a_Timeout);
    if (result.socketsSet == SOCKET_ERROR) {
        result.error = WSAGetLastError();
    } else {
        CopyOutputFds(&result.readFds, &readfds);
        CopyOutputFds(&result.writeFds, &writefds);
        CopyOutputFds(&result.exceptFds, &exceptfds);
    }
    return result;
}

Tcps_SocketError ocall_shutdown(void* a_hSocket, int a_How)
{
    SOCKET s = (SOCKET)a_hSocket;
    int err = shutdown(s, a_How);
    return (err == SOCKET_ERROR) ? (Tcps_SocketError)WSAGetLastError() : 0;
}

Tcps_SocketError ocall_closesocket(void* a_hSocket)
{
    SOCKET s = (SOCKET)a_hSocket;
    int err = closesocket(s);
    return (err == SOCKET_ERROR) ? (Tcps_SocketError)WSAGetLastError() : 0;
}

Tcps_SocketError ocall_bind(void* a_hSocket, buffer256 a_Name, int a_nNameLen)
{
    SOCKET s = (SOCKET)a_hSocket;
    int err = bind(s, (const SOCKADDR*)a_Name.buffer, a_nNameLen);
    return (err == SOCKET_ERROR) ? (Tcps_SocketError)WSAGetLastError() : 0;
}

Tcps_SocketError ocall_connect(
    void* a_hSocket,
    buffer256 a_Name,
    int a_nNameLen)
{
    SOCKET s = (SOCKET)a_hSocket;
    int err = connect(s, (const SOCKADDR*)a_Name.buffer, a_nNameLen);
    return (err == SOCKET_ERROR) ? (Tcps_SocketError)WSAGetLastError() : 0;
}

accept_Result ocall_accept(void* a_hSocket, int a_nAddrLen)
{
    SOCKET s = (SOCKET)a_hSocket;
    accept_Result result = { 0 };
    result.addrlen = a_nAddrLen;
    result.hNewSocket = (void*)accept(s, 
                                      ((a_nAddrLen > 0) ? (SOCKADDR*)result.addr : NULL),
                                      ((a_nAddrLen > 0) ? &result.addrlen : NULL));
    result.error = (result.hNewSocket == (void*)INVALID_SOCKET) ? (Tcps_SocketError)WSAGetLastError() : 0;
    return result;
}

getnameinfo_Result ocall_getnameinfo(
    buffer256 a_Addr,
    int a_AddrLen,
    int a_Flags)
{
    getnameinfo_Result result = { 0 };
    result.error = getnameinfo((const SOCKADDR*)a_Addr.buffer,
                               a_AddrLen,
                               result.host.buffer,
                               sizeof(result.host.buffer),
                               result.serv.buffer,
                               sizeof(result.serv.buffer),
                               a_Flags);
    return result;
}
