/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <sal.h>
#include <openenclave/host.h>
#include "socket_u.h"

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
    result.hSocket = (intptr_t)s;
    result.error = (s == INVALID_SOCKET) ? (oe_socket_error_t)WSAGetLastError() : 0;
    return result;
}

oe_socket_error_t ocall_listen(intptr_t a_hSocket, int a_nMaxConnections)
{
    SOCKET s = (SOCKET)a_hSocket;
    int err = listen(s, a_nMaxConnections);
    return (err == SOCKET_ERROR) ? (oe_socket_error_t)WSAGetLastError() : 0;
}

GetSockName_Result ocall_getsockname(intptr_t a_hSocket, int a_nNameLen)
{
    GetSockName_Result result = { 0 };
    SOCKET s = (SOCKET)a_hSocket;
    result.addrlen = a_nNameLen;
    int err = getsockname(s, (SOCKADDR*)result.addr, &result.addrlen);
    result.error = (err == SOCKET_ERROR) ? (oe_socket_error_t)WSAGetLastError() : 0;
    return result;
}

GetSockName_Result ocall_getpeername(intptr_t a_hSocket, int a_nNameLen)
{
    GetSockName_Result result = { 0 };
    SOCKET s = (SOCKET)a_hSocket;
    result.addrlen = a_nNameLen;
    int err = getpeername(s, (SOCKADDR*)result.addr, &result.addrlen);
    result.error = (err == SOCKET_ERROR) ? (oe_socket_error_t)WSAGetLastError() : 0;
    return result;
}

send_Result ocall_send(
    intptr_t a_hSocket,
    const void* a_Message,
    size_t a_nMessageLen,
    int a_Flags)
{
    send_Result result = { 0 };
    SOCKET s = (SOCKET)a_hSocket;

    if (a_nMessageLen > INT_MAX) {
        result.error = WSAEFAULT;
        return result;
    }

    result.bytesSent = send(s, a_Message, (int)a_nMessageLen, a_Flags);
    if (result.bytesSent == SOCKET_ERROR) {
        result.error = (oe_socket_error_t)WSAGetLastError();
    }
    return result;
}

ssize_t ocall_recv(
    _In_ intptr_t a_hSocket,
    _Out_writes_bytes_(len) void* buf,
    _In_ size_t len,
    _In_ int flags,
    _Out_ oe_socket_error_t* a_Error)
{
    SOCKET s = (SOCKET)a_hSocket;

    if (len > INT_MAX) {
        *a_Error = WSAEFAULT;
        return SOCKET_ERROR;
    }

    int bytesReceived = recv(s, buf, (int)len, flags);
    if (bytesReceived == SOCKET_ERROR) {
        *a_Error = (oe_socket_error_t)WSAGetLastError();
    } else {
        *a_Error = 0;
    }

    return bytesReceived;
}

int ocall_getaddrinfo(
    _In_z_ const char* a_NodeName,
    _In_z_ const char* a_ServiceName,
    int a_Flags,
    int a_Family,
    int a_SockType,
    int a_Protocol,
    _Out_writes_bytes_(len) addrinfo_Buffer* aibuffer,
    size_t len,
    _Out_ size_t* length_needed)
{
    struct addrinfo* ailist = NULL;
    struct addrinfo* ai;
    struct addrinfo hints = { 0 };

    int eai_error = 0;
    *length_needed = 0;
    memset(aibuffer, 0, len);

    hints.ai_flags = a_Flags;
    hints.ai_family = a_Family;
    hints.ai_socktype = a_SockType;
    hints.ai_protocol = a_Protocol;

    eai_error = getaddrinfo(a_NodeName, a_ServiceName, &hints, &ailist);
    if (ailist == NULL) {
        return eai_error;
    }

    /* Count number of addresses. */
    int count = 0;
    for (ai = ailist; ai != NULL; ai = ai->ai_next) {
        count++;
    }

    *length_needed = count * sizeof(*aibuffer);
    if (len < *length_needed) {
        freeaddrinfo(ailist);
        return EAI_AGAIN;
    }

    /* Serialize ailist. */
    int i;
    for (i = 0, ai = ailist; ai != NULL; ai = ai->ai_next, i++) {
        addrinfo_Buffer* aib = &aibuffer[i];
        aib->ai_flags = ai->ai_flags;
        aib->ai_family = ai->ai_family;
        aib->ai_socktype = ai->ai_socktype;
        aib->ai_protocol = ai->ai_protocol;
        aib->ai_addrlen = ai->ai_addrlen;
        COPY_MEMORY_BUFFER_FROM_STRING(aib->ai_canonname, (ai->ai_canonname != NULL) ? ai->ai_canonname : "");
        COPY_MEMORY_BUFFER(aib->ai_addr, ai->ai_addr, ai->ai_addrlen);
    }

    freeaddrinfo(ailist);
    return 0;
}

getsockopt_Result ocall_getsockopt(
    intptr_t a_hSocket,
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
    intptr_t a_hSocket,
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
    intptr_t a_hSocket,
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
copy_output_fds(
    _Out_ oe_fd_set_internal* dest,
    _In_ const fd_set* src)
{
    unsigned int i;
    dest->fd_count = src->fd_count;
    for (i = 0; i < src->fd_count; i++) {
        dest->fd_array[i] = (intptr_t)src->fd_array[i];
    }
    for (; i < FD_SETSIZE; i++) {
        dest->fd_array[i] = (intptr_t)NULL;
    }
}

static void
copy_input_fds(
    _Out_ fd_set* dest,
    _In_ const oe_fd_set_internal* src)
{
    unsigned int i;
    FD_ZERO(dest);
    dest->fd_count = src->fd_count;
    for (i = 0; i < src->fd_count; i++) {
        dest->fd_array[i] = src->fd_array[i];
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
    copy_input_fds(&readfds, &a_ReadFds);
    copy_input_fds(&writefds, &a_WriteFds);
    copy_input_fds(&exceptfds, &a_ExceptFds);
    result.socketsSet = select(a_nFds, &readfds, &writefds, &exceptfds, (struct timeval*)&a_Timeout);
    if (result.socketsSet == SOCKET_ERROR) {
        result.error = WSAGetLastError();
    } else {
        copy_output_fds(&result.readFds, &readfds);
        copy_output_fds(&result.writeFds, &writefds);
        copy_output_fds(&result.exceptFds, &exceptfds);
    }
    return result;
}

oe_socket_error_t ocall_shutdown(intptr_t a_hSocket, int a_How)
{
    SOCKET s = (SOCKET)a_hSocket;
    int err = shutdown(s, a_How);
    return (err == SOCKET_ERROR) ? (oe_socket_error_t)WSAGetLastError() : 0;
}

oe_socket_error_t ocall_closesocket(intptr_t a_hSocket)
{
    SOCKET s = (SOCKET)a_hSocket;
    int err = closesocket(s);
    return (err == SOCKET_ERROR) ? (oe_socket_error_t)WSAGetLastError() : 0;
}

oe_socket_error_t ocall_bind(intptr_t a_hSocket, const void* a_Name, int a_nNameLen)
{
    SOCKET s = (SOCKET)a_hSocket;
    int err = bind(s, (const SOCKADDR*)a_Name, a_nNameLen);
    return (err == SOCKET_ERROR) ? (oe_socket_error_t)WSAGetLastError() : 0;
}

oe_socket_error_t ocall_connect(
    intptr_t a_hSocket,
    const void* a_Name,
    int a_nNameLen)
{
    SOCKET s = (SOCKET)a_hSocket;
    int err = connect(s, (const SOCKADDR*)a_Name, a_nNameLen);
    return (err == SOCKET_ERROR) ? (oe_socket_error_t)WSAGetLastError() : 0;
}

accept_Result ocall_accept(intptr_t a_hSocket, int a_nAddrLen)
{
    SOCKET s = (SOCKET)a_hSocket;
    accept_Result result = { 0 };
    result.addrlen = a_nAddrLen;
    result.hNewSocket = (intptr_t)accept(s,
                                         ((a_nAddrLen > 0) ? (SOCKADDR*)result.addr : NULL),
                                         ((a_nAddrLen > 0) ? &result.addrlen : NULL));
    result.error = (result.hNewSocket == (intptr_t)INVALID_SOCKET) ? (oe_socket_error_t)WSAGetLastError() : 0;
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
