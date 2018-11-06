/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdio.h>
#include <stddef.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#include "sal_unsup.h"
#include "stdext.h"
#include "oehost.h"
#include "TcpsCalls_u.h"
#include "buffer.h"
#include "socket_u.h"

#define MAX(x,y) ((x) > (y) ? (x) : (y))

oe_socket_error_t ocall_WSAStartup(void)
{
    return 0;
}

oe_socket_error_t ocall_WSACleanup(void)
{
    return 0;
}

gethostname_Result ocall_gethostname(void)
{
    gethostname_Result result;
    int err = gethostname(result.name, sizeof(result.name));
    result.error = (err == -1) ? (oe_socket_error_t)errno : 0;
    return result;
}

socket_Result ocall_socket(
    oe_socket_address_family_t a_AddressFamily,
    oe_socket_type_t a_Type,
    int a_Protocol)
{
    socket_Result result = { 0 };
    int fd = socket(a_AddressFamily, (int)a_Type, a_Protocol);
    result.hSocket = (void *)fd;
    result.error = (fd == -1) ? (oe_socket_error_t)errno : 0;
    return result;
}

oe_socket_error_t ocall_listen(void* a_hSocket, int a_nMaxConnections)
{
    oe_socket_error_t result;
    int fd = (int)a_hSocket;
    int s = listen(fd, a_nMaxConnections);
    return s == -1 ? (oe_socket_error_t)s : 0;    
}

GetSockName_Result ocall_getsockname(void* a_hSocket, int a_nNameLen)
{
    GetSockName_Result result = { 0 };
    int fd = (int)a_hSocket;
    result.addrlen = a_nNameLen;
    int err = getsockname(fd, (struct sockaddr *)result.addr, &result.addrlen);
    result.error = (err == -1) ? (oe_socket_error_t)errno : 0;
    return result;
}

GetSockName_Result ocall_getpeername(void* a_hSocket, int a_nNameLen)
{
    GetSockName_Result result = { 0 };
    int fd = (int)a_hSocket;
    result.addrlen = a_nNameLen;
    int err = getpeername(fd, (struct sockaddr *)result.addr, &result.addrlen);
    result.error = (err == -1) ? (oe_socket_error_t)errno : 0;
    return result;
}

send_Result ocall_send(void* a_hSocket, void* a_hReeMessage, int a_Flags)
{
    send_Result result = { 0 };
    int fd = (int)a_hSocket;
    char* ptr = NULL;
    int size = 0;
    Tcps_StatusCode uStatus = GetBuffer(a_hReeMessage, &ptr, &size);
    if (Tcps_IsBad(uStatus)) {
        result.error = OE_EFAULT;
        return result;
    }
    result.bytesSent = send(fd, ptr, size, a_Flags);
    if (result.bytesSent == -1) {
        result.error = (oe_socket_error_t)errno;
    }

    return result;
}

recv_Result ocall_recv(void* a_hSocket, int a_nBufferSize, int a_Flags)
{
    recv_Result result = { 0 };
    int fd = (int)a_hSocket;
    void* hBuffer = CreateBuffer(a_nBufferSize);
    if (hBuffer == NULL) {
        result.error = OE_ENOBUFS;
        return result;
    }
    
    char* ptr = NULL;
    int size = 0;
    Tcps_StatusCode uStatus = GetBuffer(hBuffer, &ptr, &size);
    /* TODO: handle uStatus failure */
    result.bytesReceived = recv(fd, ptr, size, a_Flags);
    if (result.bytesReceived == -1) {
        result.error = (oe_socket_error_t)errno;
        FreeBuffer(hBuffer);
    } else {
        result.hMessage = hBuffer;
    }

    return result;
}

getaddrinfo_Result ocall_getaddrinfo(
    const char* a_NodeName,
    const char* a_ServiceName,
    int a_Flags,
    int a_Family,
    int a_SockType,
    int a_Protocol)
{
    Tcps_StatusCode status;
    getaddrinfo_Result result = { 0 };

    struct addrinfo *ai;
    struct addrinfo *ailist = NULL;
    struct addrinfo hints = { 0 };

    char *node_name;
    char *service_name;

    int i;
    int s;
    int size;
    void *aibufhandle;
    addrinfo_Buffer *aib;
    addrinfo_Buffer *aibuf;

    hints.ai_flags = a_Flags;
    hints.ai_family = a_Family;
    hints.ai_socktype = a_SockType;
    hints.ai_protocol = a_Protocol;

    s = getaddrinfo(a_NodeName, a_ServiceName, &hints, &ailist);
    if (s) {
        result.error = (oe_socket_error_t)s;
        return result;
    }

    for (ai = ailist; ai != NULL; ai = ai->ai_next)
    result.addressCount++;

    aibufhandle = CreateBuffer(result.addressCount * sizeof(*aibuf));
    if (!aibufhandle) {
        freeaddrinfo(ailist);
        result.error = OE_ENOBUFS;
        return result;
    }

    status = GetBuffer(aibufhandle, (char **)&aibuf, &size);
    if (Tcps_IsBad(status)) {
        FreeBuffer(aibufhandle);
        freeaddrinfo(ailist);
        result.error = OE_EFAULT;
        return result;
    }

    for (i = 0, ai = ailist; ai != NULL; ai = ai->ai_next, i++) {
        aib = &aibuf[i];
        aib->ai_flags = ai->ai_flags;
        aib->ai_family = ai->ai_family;
        aib->ai_socktype = ai->ai_socktype;
        aib->ai_protocol = ai->ai_protocol;
        aib->ai_addrlen = ai->ai_addrlen;
        COPY_MEMORY_BUFFER_FROM_STRING(aib->ai_canonname, (ai->ai_canonname != NULL) ? ai->ai_canonname : "");
        COPY_MEMORY_BUFFER(aib->ai_addr, ai->ai_addr, ai->ai_addrlen);
    }

    freeaddrinfo(ailist);

    result.hMessage = aibufhandle;
    
    return result;
}

getsockopt_Result ocall_getsockopt(
    void* a_hSocket,
    int a_nLevel,
    int a_nOptName,
    int a_nOptLen)
{
    getsockopt_Result result = { 0 };
    int fd = (int)a_hSocket;
    result.len = a_nOptLen;
    int err = getsockopt(fd, a_nLevel, a_nOptName, result.buffer, &result.len);
    result.error = (err == -1) ? (oe_socket_error_t)errno : 0;
    return result;
}

oe_socket_error_t ocall_setsockopt(
    void* a_hSocket,
    int a_nLevel,
    int a_nOptName,
    const void* a_OptVal,
    int a_nOptLen)
{
    int fd = (int)a_hSocket;
    int err = setsockopt(fd, a_nLevel, a_nOptName, a_OptVal, a_nOptLen);
    return (err == -1) ? (oe_socket_error_t)errno : 0;
}

ioctlsocket_Result ocall_ioctlsocket(
    void* a_hSocket,
    int a_nCommand,
    unsigned int a_uInputValue)
{
    ioctlsocket_Result result = { 0 };
    int fd = (int)a_hSocket;
    result.outputValue = a_uInputValue;
    int err = fcntl(fd, a_nCommand, result.outputValue);
    result.error = (err == -1) ? (oe_socket_error_t)errno : 0;
    return result;
}

static void CopyOutputFds(oe_fd_set_internal *dest, const fd_set *src, const oe_fd_set_internal *orig)
{
    unsigned int i;

    for (i = 0; i < orig->fd_count; i++) {
        dest->fd_array[i] = FD_ISSET((int)orig->fd_array[i], src)
            ? orig->fd_array[i]
            : NULL;
    }
    
    for (; i < sizeof(dest->fd_array); i++) {
        dest->fd_array[i] = NULL;
    }
}

static void CopyInputFds(fd_set *dest, const oe_fd_set_internal *src, int *nfds)
{
    unsigned int i;
    FD_ZERO(dest);
    for (i = 0; i < src->fd_count; i++) {
        FD_SET((int)src->fd_array[i], dest);
        *nfds = MAX(*nfds, (int)src->fd_array[i]);
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
    int nfds = 0;

    CopyInputFds(&readfds, &a_ReadFds, &nfds);
    CopyInputFds(&writefds, &a_WriteFds, &nfds);
    CopyInputFds(&exceptfds, &a_ExceptFds, &nfds);

    result.socketsSet = select(nfds + 1, &readfds, &writefds, &exceptfds, (struct timeval *)&a_Timeout);
    if (result.socketsSet == -1) {
        result.error = (oe_socket_error_t)errno;
    } else {
        CopyOutputFds(&result.readFds, &readfds, &a_ReadFds);
        CopyOutputFds(&result.writeFds, &writefds, &a_WriteFds);
        CopyOutputFds(&result.exceptFds, &exceptfds, &a_ExceptFds); 
    }

    return result;
}

oe_socket_error_t ocall_shutdown(void* a_hSocket, oe_shutdown_how_t a_How)
{
    int fd = (int)a_hSocket;
    int err = shutdown(fd, a_How);
    return (err == -1) ? (oe_socket_error_t)errno : 0;
}

oe_socket_error_t ocall_closesocket(void* a_hSocket)
{
    int fd = (int)a_hSocket;
    int s = close(fd);
    return s == -1 ? (oe_socket_error_t)errno : 0;
}

oe_socket_error_t ocall_bind(void* a_hSocket, const void* a_Name, int a_nNameLen)
{
    int fd = (int)a_hSocket;
    int s = bind(fd, (const struct sockaddr *)a_Name, a_nNameLen);
    return s == -1 ? (oe_socket_error_t)errno : 0;
}

oe_socket_error_t ocall_connect(
    void* a_hSocket,
    const void* a_Name,
    int a_nNameLen)
{
    int fd = (int)a_hSocket;
    int s = connect(fd, (const struct sockaddr *)a_Name, a_nNameLen);
    return s == -1 ? (oe_socket_error_t)errno : 0;
}

accept_Result ocall_accept(void* a_hSocket, int a_nAddrLen)
{
    int fd = (int)a_hSocket;
    accept_Result result = { 0 };
    result.addrlen = a_nAddrLen;
    result.hNewSocket = (void*)accept(fd, 
                                      ((a_nAddrLen > 0) ? (struct sockaddr *)result.addr : NULL),
                                      ((a_nAddrLen > 0) ? &result.addrlen : NULL));
    result.error = (result.hNewSocket == (void *)(-1)) ? (oe_socket_error_t)errno : 0;
    return result;
}

getnameinfo_Result ocall_getnameinfo(
    const void* a_Addr,
    int a_AddrLen,
    int a_Flags)
{
    getnameinfo_Result result = { 0 };
    result.error = getnameinfo((const struct sockaddr *)a_Addr,
                               a_AddrLen,
                               result.host,
                               sizeof(result.host),
                               result.serv,
                               sizeof(result.serv),
                               a_Flags);
    return result;
}
