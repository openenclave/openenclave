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
#include "linux/stdext.h"
#include <openenclave/host.h> 
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
    result.hSocket = (intptr_t)fd;
    result.error = (fd == -1) ? (oe_socket_error_t)errno : 0;
    return result;
}

oe_socket_error_t ocall_listen(intptr_t a_hSocket, int a_nMaxConnections)
{
    oe_socket_error_t result;
    int fd = (int)a_hSocket;
    int s = listen(fd, a_nMaxConnections);
    return s == -1 ? (oe_socket_error_t)s : 0;    
}

GetSockName_Result ocall_getsockname(intptr_t a_hSocket, int a_nNameLen)
{
    GetSockName_Result result = { 0 };
    int fd = (int)a_hSocket;
    result.addrlen = a_nNameLen;
    int err = getsockname(fd, (struct sockaddr *)result.addr, &result.addrlen);
    result.error = (err == -1) ? (oe_socket_error_t)errno : 0;
    return result;
}

GetSockName_Result ocall_getpeername(intptr_t a_hSocket, int a_nNameLen)
{
    GetSockName_Result result = { 0 };
    int fd = (int)a_hSocket;
    result.addrlen = a_nNameLen;
    int err = getpeername(fd, (struct sockaddr *)result.addr, &result.addrlen);
    result.error = (err == -1) ? (oe_socket_error_t)errno : 0;
    return result;
}

send_Result ocall_send(
    intptr_t a_hSocket,
    const void* a_Message,
    size_t a_nMessageLen,
    int a_Flags)
{
    send_Result result = { 0 };
    int fd = (int)a_hSocket;
    result.bytesSent = send(fd, a_Message, a_nMessageLen, a_Flags);
    if (result.bytesSent == -1) {
        result.error = (oe_socket_error_t)errno;
    }

    return result;
}

ssize_t ocall_recv(intptr_t a_hSocket, void* a_Buffer, size_t a_nBufferSize, int a_Flags, oe_socket_error_t* a_Error)
{
    int fd = (int)a_hSocket;

    ssize_t bytesReceived = recv(fd, a_Buffer, a_nBufferSize, a_Flags);
    if (bytesReceived == -1) {
        *a_Error = (oe_socket_error_t)errno;
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
    int fd = (int)a_hSocket;
    result.len = a_nOptLen;
    int err = getsockopt(fd, a_nLevel, a_nOptName, result.buffer, &result.len);
    result.error = (err == -1) ? (oe_socket_error_t)errno : 0;
    return result;
}

oe_socket_error_t ocall_setsockopt(
    intptr_t a_hSocket,
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
    intptr_t a_hSocket,
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

static void copy_output_fds(oe_fd_set_internal *dest, const fd_set *src, const oe_fd_set_internal *orig)
{
    unsigned int i;

    for (i = 0; i < orig->fd_count; i++) {
        dest->fd_array[i] = FD_ISSET((int)orig->fd_array[i], src)
            ? orig->fd_array[i]
            : 0;
    }
    
    for (; i < sizeof(dest->fd_array); i++) {
        dest->fd_array[i] = 0;
    }
}

static void copy_input_fds(fd_set *dest, const oe_fd_set_internal *src, int *nfds)
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

    copy_input_fds(&readfds, &a_ReadFds, &nfds);
    copy_input_fds(&writefds, &a_WriteFds, &nfds);
    copy_input_fds(&exceptfds, &a_ExceptFds, &nfds);

    result.socketsSet = select(nfds + 1, &readfds, &writefds, &exceptfds, (struct timeval *)&a_Timeout);
    if (result.socketsSet == -1) {
        result.error = (oe_socket_error_t)errno;
    } else {
        copy_output_fds(&result.readFds, &readfds, &a_ReadFds);
        copy_output_fds(&result.writeFds, &writefds, &a_WriteFds);
        copy_output_fds(&result.exceptFds, &exceptfds, &a_ExceptFds); 
    }

    return result;
}

oe_socket_error_t ocall_shutdown(intptr_t a_hSocket, oe_shutdown_how_t a_How)
{
    int fd = (int)a_hSocket;
    int err = shutdown(fd, a_How);
    return (err == -1) ? (oe_socket_error_t)errno : 0;
}

oe_socket_error_t ocall_closesocket(intptr_t a_hSocket)
{
    int fd = (int)a_hSocket;
    int s = close(fd);
    return s == -1 ? (oe_socket_error_t)errno : 0;
}

oe_socket_error_t ocall_bind(intptr_t a_hSocket, const void* a_Name, int a_nNameLen)
{
    int fd = (int)a_hSocket;
    int s = bind(fd, (const struct sockaddr *)a_Name, a_nNameLen);
    return s == -1 ? (oe_socket_error_t)errno : 0;
}

oe_socket_error_t ocall_connect(
    intptr_t a_hSocket,
    const void* a_Name,
    int a_nNameLen)
{
    int fd = (int)a_hSocket;
    int s = connect(fd, (const struct sockaddr *)a_Name, a_nNameLen);
    return s == -1 ? (oe_socket_error_t)errno : 0;
}

accept_Result ocall_accept(intptr_t a_hSocket, int a_nAddrLen)
{
    int fd = (int)a_hSocket;
    accept_Result result = { 0 };
    result.addrlen = a_nAddrLen;
    result.hNewSocket = (intptr_t)accept(fd, 
                                         ((a_nAddrLen > 0) ? (struct sockaddr *)result.addr : NULL),
                                         ((a_nAddrLen > 0) ? &result.addrlen : NULL));
    result.error = (result.hNewSocket == (intptr_t)(-1)) ? (oe_socket_error_t)errno : 0;
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
