/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <openenclave/host.h>
#include "../socket_u.h"
#include "../../buffer.h"

oe_socket_error_t ocall_WSAStartup(void)
{
    WSADATA wsaData;
    int apiResult = WSAStartup(0x202, &wsaData);
    return (oe_socket_error_t)apiResult;
}

int ocall_WSACleanup(void)
{
    return WSACleanup();
}

gethostname_Result ocall_gethostname(void)
{
    gethostname_Result result;
    int err = gethostname(result.name, sizeof(result.name));
    result.error = (err != 0) ? (oe_socket_error_t)WSAGetLastError() : 0;
    return result;
}

socket_Result ocall_socket(
    oe_socket_address_family_t a_AddressFamily,
    oe_socket_type_t a_Type,
    int a_Protocol)
{
    socket_Result result = { 0 };
    SOCKET s = socket(a_AddressFamily, a_Type, a_Protocol);
    result.hSocket = (void*)s;
    result.error = (s == INVALID_SOCKET) ? (oe_socket_error_t)WSAGetLastError() : 0;
    return result;
}

oe_socket_error_t ocall_listen(void* a_hSocket, int a_nMaxConnections)
{
    SOCKET s = (SOCKET)a_hSocket;
    int err = listen(s, a_nMaxConnections);
    return (err == SOCKET_ERROR) ? (oe_socket_error_t)WSAGetLastError() : 0;
}

GetSockName_Result ocall_getsockname(void* a_hSocket, int a_nNameLen)
{
    GetSockName_Result result = { 0 };
    SOCKET s = (SOCKET)a_hSocket;
    result.addrlen = a_nNameLen;
    int err = getsockname(s, (SOCKADDR*)result.addr, &result.addrlen);
    result.error = (err == SOCKET_ERROR) ? (oe_socket_error_t)WSAGetLastError() : 0;
    return result;
}

GetSockName_Result ocall_getpeername(void* a_hSocket, int a_nNameLen)
{
    GetSockName_Result result = { 0 };
    SOCKET s = (SOCKET)a_hSocket;
    result.addrlen = a_nNameLen;
    int err = getpeername(s, (SOCKADDR*)result.addr, &result.addrlen);
    result.error = (err == SOCKET_ERROR) ? (oe_socket_error_t)WSAGetLastError() : 0;
    return result;
}

send_Result ocall_send(void* a_hSocket, void* a_hReeMessage, int a_Flags)
{
    send_Result result = { 0 };
    SOCKET s = (SOCKET)a_hSocket;
    char* ptr = NULL;
    int size = 0;
    oe_result_t uStatus = GetBuffer(a_hReeMessage, &ptr, &size);
    if (uStatus != OE_OK) {
        result.error = WSAEFAULT;
        return result;
    }
    result.bytesSent = send(s, ptr, size, a_Flags);
    if (result.bytesSent == SOCKET_ERROR) {
        result.error = (oe_socket_error_t)WSAGetLastError();
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
    oe_result_t uStatus = GetBuffer(hBuffer, &ptr, &size);
    /* TODO: handle uStatus failure */
    result.bytesReceived = recv(s, ptr, size, a_Flags);
    if (result.bytesReceived == SOCKET_ERROR) {
        result.error = (oe_socket_error_t)WSAGetLastError();
        FreeBuffer(hBuffer);
    } else {
        result.hMessage = hBuffer;
    }
    return result;
}

getaddrinfo_Result ocall_getaddrinfo(
    _In_z_ const char* a_NodeName,
    _In_z_ const char* a_ServiceName,
    _In_ int a_Flags,
    _In_ int a_Family,
    _In_ int a_SockType,
    _In_ int a_Protocol)
{
    getaddrinfo_Result result = { 0 };
    ADDRINFO* ailist = NULL;
    ADDRINFO* ai;
    ADDRINFO hints = { 0 };
    void* hBuffer = NULL;

    hints.ai_flags = a_Flags;
    hints.ai_family = a_Family;
    hints.ai_socktype = a_SockType;
    hints.ai_protocol = a_Protocol;

    result.error = getaddrinfo(a_NodeName, a_ServiceName, &hints, &ailist);
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
    oe_result_t uStatus = GetBuffer(hBuffer, (char**)&aibuffer, &size);
    /* TODO: handle uStatus failure */
    int i;
    for (i = 0, ai = ailist; ai != NULL; ai = ai->ai_next, i++) {
        addrinfo_Buffer* aib = &aibuffer[i];
        aib->ai_flags = ai->ai_flags; 
        aib->ai_family = ai->ai_family; 
        aib->ai_socktype = ai->ai_socktype; 
        aib->ai_protocol = ai->ai_protocol; 
        aib->ai_addrlen = (int)ai->ai_addrlen; 
        COPY_MEMORY_BUFFER_FROM_STRING(aib->ai_canonname, (ai->ai_canonname != NULL) ? ai->ai_canonname : "");
        COPY_MEMORY_BUFFER(aib->ai_addr, ai->ai_addr, ai->ai_addrlen);
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
    result.error = (err == SOCKET_ERROR) ? (oe_socket_error_t)WSAGetLastError() : 0;
    return result;
}

oe_socket_error_t ocall_setsockopt(
    void* a_hSocket,
    int a_nLevel,
    int a_nOptName,
    const void* a_OptVal,
    int a_nOptLen)
{
    SOCKET s = (SOCKET)a_hSocket;
    int err = setsockopt(s, a_nLevel, a_nOptName, a_OptVal, a_nOptLen);
    return (err == SOCKET_ERROR) ? (oe_socket_error_t)WSAGetLastError() : 0;
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
    result.error = (err == SOCKET_ERROR) ? (oe_socket_error_t)WSAGetLastError() : 0;
    return result;
}

static void
CopyOutputFds(
    _Out_ oe_fd_set_internal* dest,
    _In_ const fd_set* src)
{
    unsigned int i;
    dest->fd_count = src->fd_count;
    for (i = 0; i < src->fd_count; i++) {
        dest->fd_array[i] = (void*)src->fd_array[i];
    }
    for (; i < FD_SETSIZE; i++) {
        dest->fd_array[i] = NULL;
    }
}

static void
CopyInputFds(
    _Out_ fd_set* dest,
    _In_ const oe_fd_set_internal* src)
{
    unsigned int i;
    FD_ZERO(dest);
    dest->fd_count = src->fd_count;
    for (i = 0; i < src->fd_count; i++) {
        (void*)dest->fd_array[i] = src->fd_array[i];
    }
}

select_Result ocall_select(
    int a_nFds,
    oe_fd_set_internal a_ReadFds,
    oe_fd_set_internal a_WriteFds,
    oe_fd_set_internal a_ExceptFds,
    struct timeval a_Timeout)
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

oe_socket_error_t ocall_shutdown(void* a_hSocket, int a_How)
{
    SOCKET s = (SOCKET)a_hSocket;
    int err = shutdown(s, a_How);
    return (err == SOCKET_ERROR) ? (oe_socket_error_t)WSAGetLastError() : 0;
}

oe_socket_error_t ocall_closesocket(void* a_hSocket)
{
    SOCKET s = (SOCKET)a_hSocket;
    int err = closesocket(s);
    return (err == SOCKET_ERROR) ? (oe_socket_error_t)WSAGetLastError() : 0;
}

oe_socket_error_t ocall_bind(void* a_hSocket, const void* a_Name, int a_nNameLen)
{
    SOCKET s = (SOCKET)a_hSocket;
    int err = bind(s, (const SOCKADDR*)a_Name, a_nNameLen);
    return (err == SOCKET_ERROR) ? (oe_socket_error_t)WSAGetLastError() : 0;
}

oe_socket_error_t ocall_connect(
    void* a_hSocket,
    const void* a_Name,
    int a_nNameLen)
{
    SOCKET s = (SOCKET)a_hSocket;
    int err = connect(s, (const SOCKADDR*)a_Name, a_nNameLen);
    return (err == SOCKET_ERROR) ? (oe_socket_error_t)WSAGetLastError() : 0;
}

accept_Result ocall_accept(void* a_hSocket, int a_nAddrLen)
{
    SOCKET s = (SOCKET)a_hSocket;
    accept_Result result = { 0 };
    result.addrlen = a_nAddrLen;
    result.hNewSocket = (void*)accept(s, 
                                      ((a_nAddrLen > 0) ? (SOCKADDR*)result.addr : NULL),
                                      ((a_nAddrLen > 0) ? &result.addrlen : NULL));
    result.error = (result.hNewSocket == (void*)INVALID_SOCKET) ? (oe_socket_error_t)WSAGetLastError() : 0;
    return result;
}

getnameinfo_Result ocall_getnameinfo(
    const void* a_Addr,
    int a_AddrLen,
    int a_Flags)
{
    getnameinfo_Result result = { 0 };
    result.error = getnameinfo((const SOCKADDR*)a_Addr,
                               a_AddrLen,
                               result.host,
                               sizeof(result.host),
                               result.serv,
                               sizeof(result.serv),
                               a_Flags);
    return result;
}
