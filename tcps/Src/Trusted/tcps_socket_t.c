/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include "tcps_socket_t.h"
#include "tcps_string_t.h"
#include "TcpsCalls_t.h"
#include <errno.h>

static void
CopyInputFds(Tcps_FdSet* dest, fd_set* src)
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
CopyOutputFds(fd_set* dest, Tcps_FdSet* src)
{
    unsigned int i;
    dest->fd_count = src->count;
    for (i = 0; i < src->count; i++) {
        dest->fd_array[i] = (TCPS_SOCKET)src->fdArray[i];
    }
}

int
Tcps_select(
    _In_ int a_nFds,
    _Inout_opt_ Tcps_fd_set* a_readfds,
    _Inout_opt_ Tcps_fd_set* a_writefds,
    _Inout_opt_ Tcps_fd_set* a_exceptfds,
    _In_opt_ const struct timeval* a_Timeout)
{
    select_Result result = { 0 };
    Tcps_FdSet readFds = { 0 };
    Tcps_FdSet writeFds = { 0 };
    Tcps_FdSet exceptFds = { 0 };
    if (a_readfds != NULL) {
        CopyInputFds(&readFds, a_readfds);
    }
    if (a_writefds != NULL) {
        CopyInputFds(&writeFds, a_writefds);
    }
    if (a_exceptfds != NULL) {
        CopyInputFds(&exceptFds, a_exceptfds);
    }
    sgx_status_t sgxStatus = ocall_select(&result, a_nFds, readFds, writeFds, exceptFds, *(Tcps_Timeval*)a_Timeout);
    if (sgxStatus != SGX_SUCCESS) {
        return 0;
    }

    if (result.error != 0) {
        return 0;
    }

    if (a_readfds != NULL) {
        CopyOutputFds(a_readfds, &result.readFds);
    }
    if (a_writefds != NULL) {
        CopyOutputFds(a_writefds, &result.writeFds);
    }
    if (a_exceptfds != NULL) {
        CopyOutputFds(a_exceptfds, &result.exceptFds);
    }
    return result.socketsSet;
}

int Tcps_FDIsSet(_In_ TCPS_SOCKET fd, _In_ fd_set* set)
{
    unsigned int i;
    for (i = 0; i < set->fd_count; i++) {
        if (fd == set->fd_array[i]) {
            return TRUE;
        }
    }
    return FALSE;
}

int
Tcps_gethostname(
    _Out_writes_(a_uiBufferLength) char* a_pBuffer,
    _In_ size_t a_uiBufferLength)
{
    sgx_status_t sgxStatus;
    gethostname_Result result;

    sgxStatus = ocall_gethostname(&result);
    if (sgxStatus != SGX_SUCCESS) {
        result.error = TCPS_WSAENETDOWN;
    }
    if (result.error == 0) {
        strncpy(a_pBuffer, result.name, a_uiBufferLength);
    }
    Tcps_WSASetLastError(result.error);
    return (result.error == 0) ? 0 : TCPS_SOCKET_ERROR;
}

int
Tcps_WSAStartup(
    _In_ uint16_t wVersionRequired,
    _Out_ TCPS_WSADATA* lpWSAData)
{
    Tcps_SocketError apiResult;
    sgx_status_t sgxStatus = ocall_WSAStartup(&apiResult);
    if (sgxStatus == SGX_SUCCESS && apiResult == 0) {
        return 0;
    }
    return TCPS_WSASYSNOTREADY;
}

int
Tcps_WSACleanup(void)
{
    Tcps_SocketError error;
    sgx_status_t sgxStatus = ocall_WSACleanup(&error);
    if (sgxStatus != SGX_SUCCESS) {
        error = TCPS_WSAENETDOWN;
    }
    Tcps_WSASetLastError(error);
    return (error == 0) ? 0 : TCPS_SOCKET_ERROR;
}

/* We use a simple global variable since we're single threaded. */
static Tcps_SocketError g_WSALastError = 0;

void
Tcps_WSASetLastError(_In_ int iError)
{
    g_WSALastError = iError;
}

int
Tcps_WSAGetLastError(void)
{
    return g_WSALastError;
}

int
Tcps_shutdown(
    _In_ TCPS_SOCKET s,
    _In_ int how)
{
    Tcps_SocketError socketError = 0;
    sgx_status_t sgxStatus = ocall_shutdown(&socketError, s, how);
    if (sgxStatus != SGX_SUCCESS) {
        socketError = TCPS_WSAENETDOWN;
    }
    Tcps_WSASetLastError(socketError);
    return (socketError == 0) ? 0 : TCPS_SOCKET_ERROR;
}

int 
Tcps_closesocket(
    _In_ TCPS_SOCKET s)
{
    Tcps_SocketError socketError = 0;
    sgx_status_t sgxStatus = ocall_closesocket(&socketError, s);
    if (sgxStatus != SGX_SUCCESS) {
        socketError = TCPS_WSAENETDOWN;
    }
    Tcps_WSASetLastError(socketError);
    return (socketError == 0) ? 0 : TCPS_SOCKET_ERROR;
}

int
Tcps_listen(
    _In_ TCPS_SOCKET s,
    _In_ int backlog)
{
    Tcps_SocketError socketError = 0;
    sgx_status_t sgxStatus = ocall_listen(&socketError, s, backlog);
    if (sgxStatus != SGX_SUCCESS) {
        socketError = TCPS_WSAENETDOWN;
    }
    Tcps_WSASetLastError(socketError);
    return (socketError == 0) ? 0 : TCPS_SOCKET_ERROR;
}

int
Tcps_getsockopt(
    _In_ TCPS_SOCKET s,
    _In_ int level,
    _In_ int optname,
    _Out_writes_(*optlen) char *optval,
    _Inout_ int *optlen)
{
    getsockopt_Result result = { 0 };
    if (*optlen > sizeof(result.buffer)) {
        Tcps_WSASetLastError(TCPS_WSAEINVAL);
        return TCPS_SOCKET_ERROR;
    }
    sgx_status_t sgxStatus = ocall_getsockopt(&result, s, level, optname, *optlen);
    if ((sgxStatus != SGX_SUCCESS) || (result.len > *optlen)) {
        result.error = TCPS_WSAENETDOWN;
        *optlen = 0;
    } else {
        *optlen = result.len;
        memcpy(optval, result.buffer, result.len);
    }
    Tcps_WSASetLastError(result.error);
    return (result.error == 0) ? 0 : TCPS_SOCKET_ERROR;
}

TCPS_SOCKET
Tcps_socket(
    _In_ Tcps_sa_family_t af,
    _In_ int type,
    _In_ int protocol)
{
    socket_Result result;
    sgx_status_t sgxStatus = ocall_socket(&result, af, type, protocol);
    if (sgxStatus != SGX_SUCCESS) {
        result.error = TCPS_WSAENETDOWN;
        result.hSocket = TCPS_INVALID_SOCKET;
    }
    Tcps_WSASetLastError(result.error);
    return result.hSocket;
}

int
Tcps_recv(
    _In_ TCPS_SOCKET s,
    _Out_writes_(len) char *buf,
    _In_ int len,
    _In_ int flags)
{
    int bytesReceived = TCPS_SOCKET_ERROR;
    sgx_status_t sgxStatus;
    recv_Result result;

    result.bytesReceived = 0;

    sgxStatus = ocall_recv(&result, s, len, flags);
    if ((sgxStatus != SGX_SUCCESS) || (result.bytesReceived > len))
    {
        result.error = TCPS_WSAENETDOWN;
    }
    else if (result.bytesReceived > 0)
    {
        Tcps_StatusCode uStatus = TcpsPullDataFromReeBuffer(
            result.hMessage,
            buf,
            result.bytesReceived);

        TcpsFreeReeBuffer(result.hMessage);

        if (Tcps_IsBad(uStatus))
        {
            result.error = TCPS_WSAENETDOWN;
        }
    }
    WSASetLastError(result.error);
    bytesReceived = (result.error != 0) ? TCPS_SOCKET_ERROR : result.bytesReceived;
    return bytesReceived;
}

int
Tcps_send(
    _In_ TCPS_SOCKET s,
    _In_reads_bytes_(len) const char *buf,
    _In_ int len,
    _In_ int flags)
{
    sgx_status_t sgxStatus;
    send_Result result;
    void* hReeBuffer; /* Handle to REE buffer. */

    Tcps_StatusCode uStatus = TcpsPushDataToReeBuffer(buf, len, &hReeBuffer);
    if (Tcps_IsBad(uStatus))
    {
        result.error = TCPS_WSAENETDOWN;
        result.bytesSent = 0;
    }
    else
    {
        sgxStatus = ocall_send(&result, s, hReeBuffer, flags);

        TcpsFreeReeBuffer(hReeBuffer);

        if (sgxStatus != SGX_SUCCESS)
        {
            result.error = TCPS_WSAENETDOWN;
            result.bytesSent = 0;
        }
    }
    WSASetLastError(result.error);
    return (result.error != 0) ? TCPS_SOCKET_ERROR : result.bytesSent;
}

static uint32_t swap_uint32(uint32_t const net)
{
    uint8_t data[4];
    memcpy(&data, &net, sizeof(data));

    return ((uint32_t)data[3] << 0)
        | ((uint32_t)data[2] << 8)
        | ((uint32_t)data[1] << 16)
        | ((uint32_t)data[0] << 24);
}

static uint32_t swap_uint16(uint16_t const net)
{
    uint8_t data[2];
    memcpy(&data, &net, sizeof(data));

    return ((uint16_t)data[1] << 0)
        | ((uint16_t)data[0] << 8);
}

uint32_t
Tcps_ntohl(
    _In_ uint32_t netLong)
{
    return swap_uint32(netLong);
}

uint16_t
Tcps_ntohs(
    _In_ uint16_t netShort)
{
    return swap_uint16(netShort);
}

uint32_t
Tcps_htonl(
    _In_ uint32_t hostLong)
{
    return swap_uint32(hostLong);
}

uint16_t
Tcps_htons(
    _In_ uint16_t hostShort)
{
    return swap_uint16(hostShort);
}

int
Tcps_setsockopt(
    _In_ TCPS_SOCKET s,
    _In_ int level,
    _In_ int optname,
    _In_reads_bytes_(optlen) const char* optval,
    _In_ int optlen)
{
    Tcps_SocketError socketError = 0;
    buffer256 optBuffer;
    sgx_status_t sgxStatus;

    COPY_BUFFER(optBuffer, optval, optlen);

    sgxStatus = ocall_setsockopt(&socketError, s, level, optname, optBuffer, optlen);
    if (sgxStatus != SGX_SUCCESS) {
        socketError = TCPS_WSAENETDOWN;
    }
    Tcps_WSASetLastError(socketError);
    return (socketError == 0) ? 0 : TCPS_SOCKET_ERROR;
}

int
Tcps_ioctlsocket(
    _In_ TCPS_SOCKET s,
    _In_ long cmd,
    _Inout_ u_long *argp)
{
    ioctlsocket_Result result = {0};
    sgx_status_t sgxStatus;

    sgxStatus = ocall_ioctlsocket(&result, s, cmd, *argp);
    if (sgxStatus != SGX_SUCCESS) {
        result.error = TCPS_WSAENETDOWN;
    }
    Tcps_WSASetLastError(result.error);
    *argp = result.outputValue;
    return (result.error == 0) ? 0 : TCPS_SOCKET_ERROR;
}

int
Tcps_connect(
    _In_ TCPS_SOCKET s,
    _In_reads_bytes_(namelen) const Tcps_sockaddr *name,
    _In_ int namelen)
{
    Tcps_SocketError socketError = 0;
    buffer256 nameBuffer;
    sgx_status_t sgxStatus;

    COPY_BUFFER(nameBuffer, (const char*)name, namelen);

    sgxStatus = ocall_connect(&socketError, s, nameBuffer, namelen);
    if (sgxStatus != SGX_SUCCESS) {
        socketError = TCPS_WSAENETDOWN;
    }
    Tcps_WSASetLastError(socketError);
    return (socketError == 0) ? 0 : TCPS_SOCKET_ERROR;
}

TCPS_SOCKET
Tcps_accept(
    _In_ TCPS_SOCKET a_Socket,
    _Out_writes_bytes_(*addrlen) struct sockaddr* a_SockAddr,
    _Inout_ int *a_pAddrLen)
{
    accept_Result result;
    int addrlen = (a_pAddrLen != NULL) ? *a_pAddrLen : 0;
    sgx_status_t sgxStatus = ocall_accept(&result, a_Socket, addrlen);
    if ((sgxStatus != SGX_SUCCESS) || (result.addrlen > addrlen)) {
        result.error = TCPS_WSAENETDOWN;
        addrlen = 0;
    } else {
        memcpy(a_SockAddr, result.addr, result.addrlen);
        addrlen = result.addrlen;
    }
    Tcps_WSASetLastError(result.error);
    if (a_pAddrLen != NULL) {
        *a_pAddrLen = addrlen;
    }
    return (result.error == 0) ? result.hNewSocket : TCPS_INVALID_SOCKET;
}

int
Tcps_getpeername(
    _In_ TCPS_SOCKET s,
    _Out_writes_bytes_(*addrlen) struct sockaddr* addr,
    _Inout_ int *addrlen)
{
    GetSockName_Result result;
    sgx_status_t sgxStatus = ocall_getpeername(&result, s, *addrlen);
    if ((sgxStatus != SGX_SUCCESS) || (result.addrlen > *addrlen)) {
        result.error = TCPS_WSAENETDOWN;
        *addrlen = 0;
    } else {
        memcpy(addr, result.addr, result.addrlen);
        *addrlen = result.addrlen;
    }
    Tcps_WSASetLastError(result.error);
    return (result.error == 0) ? 0 : TCPS_SOCKET_ERROR;
}

int
Tcps_getsockname(
    _In_ TCPS_SOCKET s,
    _Out_writes_bytes_(*addrlen) struct sockaddr* addr,
    _Inout_ int *addrlen)
{
    GetSockName_Result result;
    sgx_status_t sgxStatus = ocall_getsockname(&result, s, *addrlen);
    if ((sgxStatus != SGX_SUCCESS) || (result.addrlen > *addrlen)) {
        result.error = TCPS_WSAENETDOWN;
        *addrlen = 0;
    } else {
        memcpy(addr, result.addr, result.addrlen);
        *addrlen = result.addrlen;
    }
    Tcps_WSASetLastError(result.error);
    return (result.error == 0) ? 0 : TCPS_SOCKET_ERROR;
}

int
Tcps_bind(
    _In_ TCPS_SOCKET s,
    _In_reads_bytes_(namelen) const Tcps_sockaddr *name,
    _In_ int namelen)
{
    Tcps_SocketError socketError = 0;
    buffer256 nameBuffer;
    sgx_status_t sgxStatus;

    COPY_BUFFER(nameBuffer, (const char*)name, namelen);

    sgxStatus = ocall_bind(&socketError, s, nameBuffer, namelen);
    if (sgxStatus != SGX_SUCCESS) {
        socketError = TCPS_WSAENETDOWN;
    }
    Tcps_WSASetLastError(socketError);
    return (socketError == 0) ? 0 : TCPS_SOCKET_ERROR;
}

uint32_t
Tcps_inet_addr(
    _In_z_ const char *cp)
{
    /* We only support dotted decimal. */
    uint8_t byte[4];
    int field = 0;
    const char* next;
    const char* p = cp;

    for (p = cp; field < 4; p = next) {
        const char* dot = strchr(p, '.');
        next = (dot != NULL) ? dot + 1 : p + strlen(p);
        byte[field++] = (uint8_t)atoi(p);
    }
    if (*p != 0) {
        return INADDR_NONE;
    }
    return *(uint32_t*)byte;
}

void
Tcps_freeaddrinfo(
    _In_ Tcps_addrinfo* ailist)
{
    Tcps_addrinfo* ai;
    Tcps_addrinfo* next;

    for (ai = ailist; ai != NULL; ai = next) {
        next = ai->ai_next;
        if (ai->ai_canonname != NULL) {
            free(ai->ai_canonname);
        }
        if (ai->ai_addr != NULL) {
            free(ai->ai_addr);
        }
        free(ai);
        ailist = next;
    }
}

int
Tcps_getaddrinfo(
    _In_z_ const char* pNodeName,
    _In_z_ const char* pServiceName,
    _In_ const Tcps_addrinfo* pHints,
    _Out_ Tcps_addrinfo** ppResult)
{
    int bytesReceived = TCPS_SOCKET_ERROR;
    sgx_status_t sgxStatus;
    getaddrinfo_Result result;
    Tcps_addrinfo* ailist = NULL;
    Tcps_addrinfo* ai;
    Tcps_addrinfo** pNext = &ailist;
    buffer256 nodeName;
    buffer256 serviceName;
    Tcps_StatusCode uStatus = Tcps_Good;

    result.addressCount = 0;

    COPY_BUFFER_FROM_STRING(nodeName, (pNodeName != NULL) ? pNodeName : "");
    COPY_BUFFER_FROM_STRING(serviceName, (pServiceName != NULL) ? pServiceName : "");

    sgxStatus = ocall_getaddrinfo(
        &result,
        nodeName,
        serviceName,
        (pHints != NULL) ? pHints->ai_flags : 0,
        (pHints != NULL) ? pHints->ai_family : 0,
        (pHints != NULL) ? pHints->ai_socktype : 0,
        (pHints != NULL) ? pHints->ai_protocol : 0);
    if (sgxStatus != SGX_SUCCESS) {
        result.error = TCPS_WSANO_RECOVERY;
    }

    if (result.addressCount > 0) {
        int bytesReceived = result.addressCount * sizeof(addrinfo_Buffer);
        char* buf = malloc(bytesReceived);
        if (buf == NULL) {
            uStatus = Tcps_BadOutOfMemory;
            result.error = TCPS_WSA_NOT_ENOUGH_MEMORY;
        } else {
            uStatus = TcpsPullDataFromReeBuffer(
                result.hMessage,
                buf,
                bytesReceived);
            if (Tcps_IsBad(uStatus))
            {
                result.error = TCPS_WSANO_RECOVERY;
            }
        }

        TcpsFreeReeBuffer(result.hMessage);

        struct addrinfo_Buffer* response = (struct addrinfo_Buffer*)buf;

        /* We now have a response to deserialize. */
        for (int i = 0; i < result.addressCount; i++) {
            if (response[i].ai_addrlen > sizeof(Tcps_sockaddr_storage) ||
                response[i].ai_addrlen > sizeof(response[i].ai_addr)) {
                result.error = TCPS_WSA_NOT_ENOUGH_MEMORY;
                break;
            }
            ai = malloc(sizeof(*ai));
            if (ai == NULL) {
                result.error = TCPS_WSA_NOT_ENOUGH_MEMORY;
                break;
            }
            ai->ai_addr = malloc(response[i].ai_addrlen);
            if (ai->ai_addr == NULL) {
                free(ai);
                result.error = TCPS_WSA_NOT_ENOUGH_MEMORY;
                break;
            }
            memcpy(ai->ai_addr, response[i].ai_addr.buffer, response[i].ai_addrlen);

            ai->ai_flags = response[i].ai_flags;
            ai->ai_family = response[i].ai_family;
            ai->ai_socktype = response[i].ai_socktype;
            ai->ai_protocol = response[i].ai_protocol;
            ai->ai_addrlen = response[i].ai_addrlen;
            if (response[i].ai_canonname.buffer[0] != 0) {
                ai->ai_canonname = malloc(sizeof(response[i].ai_canonname) + 1);
                if (ai->ai_canonname == NULL) {
                    free(ai);
                    result.error = TCPS_WSA_NOT_ENOUGH_MEMORY;
                    break;
                }
                strncpy(ai->ai_canonname, response[i].ai_canonname.buffer,
                        sizeof(response[i].ai_canonname));
                ai->ai_canonname[sizeof(response[i].ai_canonname)] = 0;
            } else {
                ai->ai_canonname = NULL;
            }
            ai->ai_next = NULL;

            /* Insert at end of list. */
            *pNext = ai;
            pNext = &ai->ai_next;
        }
    }
    WSASetLastError(result.error);

    if (result.error != 0 && ailist != NULL) {
        freeaddrinfo(ailist);
    } else {
        *ppResult = ailist;
    }
    return result.error;
}

int
Tcps_getnameinfo(
    _In_ const struct Tcps_sockaddr *sa,
    _In_ Tcps_socklen_t salen,
    _Out_writes_opt_z_(hostlen) char* host,
    _In_ size_t hostlen,
    _Out_writes_opt_z_(servlen) char* serv,
    _In_ size_t servlen,
    _In_ int flags)
{
    getnameinfo_Result result = { 0 };
    buffer256 addrBuffer;
    sgx_status_t sgxStatus;

    COPY_BUFFER(addrBuffer, (const char*)sa, salen);

    sgxStatus = ocall_getnameinfo(&result, addrBuffer, salen, flags);
    if (sgxStatus != SGX_SUCCESS) {
        result.error = TCPS_WSANO_RECOVERY;
    }

    if (host != NULL) {
        strncpy(host, result.host.buffer, hostlen);
        host[hostlen - 1] = 0;
    }

    if (serv != NULL) {
        strncpy(serv, result.serv.buffer, servlen);
        serv[servlen - 1] = 0;
    }

    return result.error;
}
