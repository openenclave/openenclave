/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <openenclave/enclave.h>
#include "enclavelibc.h"
#include "tcps_string_t.h"
#include "oeoverintelsgx_t.h"
#include "socket_t.h"
#include <errno.h>

void ecall_InitializeSockets() {}

static void
CopyInputFds(oe_fd_set_internal* dest, oe_fd_set* src)
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
CopyOutputFds(oe_fd_set* dest, oe_fd_set_internal* src)
{
    unsigned int i;
    dest->fd_count = src->fd_count;
    for (i = 0; i < src->fd_count; i++) {
        dest->fd_array[i] = (oe_socket_t)src->fd_array[i];
    }
}

int
oe_select(
    _In_ int a_nFds,
    _Inout_opt_ oe_fd_set* a_readfds,
    _Inout_opt_ oe_fd_set* a_writefds,
    _Inout_opt_ oe_fd_set* a_exceptfds,
    _In_opt_ const struct timeval* a_Timeout)
{
    select_Result result = { 0 };
    oe_fd_set_internal readFds = { 0 };
    oe_fd_set_internal writeFds = { 0 };
    oe_fd_set_internal exceptFds = { 0 };
    if (a_readfds != NULL) {
        CopyInputFds(&readFds, a_readfds);
    }
    if (a_writefds != NULL) {
        CopyInputFds(&writeFds, a_writefds);
    }
    if (a_exceptfds != NULL) {
        CopyInputFds(&exceptFds, a_exceptfds);
    }
    sgx_status_t sgxStatus = ocall_select(&result, a_nFds, readFds, writeFds, exceptFds, *(struct timeval*)a_Timeout);
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

int oe_fd_isset(_In_ oe_socket_t fd, _In_ fd_set* set)
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
oe_gethostname(
    _Out_writes_(a_uiBufferLength) char* a_pBuffer,
    _In_ size_t a_uiBufferLength)
{
    sgx_status_t sgxStatus;
    gethostname_Result result;

    sgxStatus = ocall_gethostname(&result);
    if (sgxStatus != SGX_SUCCESS) {
        result.error = OE_ENETDOWN;
    }
    if (result.error == 0) {
        strncpy(a_pBuffer, result.name, a_uiBufferLength);
    }
    oe_wsa_set_last_error(result.error);
    return (result.error == 0) ? 0 : OE_SOCKET_ERROR;
}

int
oe_wsa_startup(
    _In_ uint16_t wVersionRequired,
    _Out_ oe_wsa_data_t* lpWSAData)
{
    oe_socket_error_t apiResult;
    sgx_status_t sgxStatus = ocall_WSAStartup(&apiResult);
    if (sgxStatus == SGX_SUCCESS && apiResult == 0) {
        return 0;
    }
    return OE_SYSNOTREADY;
}

int
oe_wsa_cleanup(void)
{
    oe_socket_error_t error;
    sgx_status_t sgxStatus = ocall_WSACleanup(&error);
    if (sgxStatus != SGX_SUCCESS) {
        error = OE_ENETDOWN;
    }
    oe_wsa_set_last_error(error);
    return (error == 0) ? 0 : OE_SOCKET_ERROR;
}

/* We use a simple global variable since we're single threaded. */
static oe_socket_error_t g_WSALastError = 0;

void
oe_wsa_set_last_error(_In_ int iError)
{
    g_WSALastError = iError;
}

int
oe_wsa_get_last_error(void)
{
    return g_WSALastError;
}

int
oe_shutdown(
    _In_ oe_socket_t s,
    _In_ int how)
{
    oe_socket_error_t socketError = 0;
    sgx_status_t sgxStatus = ocall_shutdown(&socketError, s, how);
    if (sgxStatus != SGX_SUCCESS) {
        socketError = OE_ENETDOWN;
    }
    oe_wsa_set_last_error(socketError);
    return (socketError == 0) ? 0 : OE_SOCKET_ERROR;
}

int 
oe_closesocket(
    _In_ oe_socket_t s)
{
    oe_socket_error_t socketError = 0;
    sgx_status_t sgxStatus = ocall_closesocket(&socketError, s);
    if (sgxStatus != SGX_SUCCESS) {
        socketError = OE_ENETDOWN;
    }
    oe_wsa_set_last_error(socketError);
    return (socketError == 0) ? 0 : OE_SOCKET_ERROR;
}

int
oe_listen(
    _In_ oe_socket_t s,
    _In_ int backlog)
{
    oe_socket_error_t socketError = 0;
    sgx_status_t sgxStatus = ocall_listen(&socketError, s, backlog);
    if (sgxStatus != SGX_SUCCESS) {
        socketError = OE_ENETDOWN;
    }
    oe_wsa_set_last_error(socketError);
    return (socketError == 0) ? 0 : OE_SOCKET_ERROR;
}

int
oe_getsockopt(
    _In_ oe_socket_t s,
    _In_ int level,
    _In_ int optname,
    _Out_writes_(*optlen) char *optval,
    _Inout_ int *optlen)
{
    getsockopt_Result result = { 0 };
    if (*optlen > sizeof(result.buffer)) {
        oe_wsa_set_last_error(OE_EINVAL);
        return OE_SOCKET_ERROR;
    }
    sgx_status_t sgxStatus = ocall_getsockopt(&result, s, level, optname, *optlen);
    if ((sgxStatus != SGX_SUCCESS) || (result.len > *optlen)) {
        result.error = OE_ENETDOWN;
        *optlen = 0;
    } else {
        *optlen = result.len;
        memcpy(optval, result.buffer, result.len);
    }
    oe_wsa_set_last_error(result.error);
    return (result.error == 0) ? 0 : OE_SOCKET_ERROR;
}

oe_socket_t
oe_socket(
    _In_ oe_sa_family_t af,
    _In_ int type,
    _In_ int protocol)
{
    socket_Result result;
    sgx_status_t sgxStatus = ocall_socket(&result, af, type, protocol);
    if (sgxStatus != SGX_SUCCESS) {
        result.error = OE_ENETDOWN;
        result.hSocket = OE_INVALID_SOCKET;
    }
    oe_wsa_set_last_error(result.error);
    return result.hSocket;
}

int
oe_recv(
    _In_ oe_socket_t s,
    _Out_writes_(len) char *buf,
    _In_ int len,
    _In_ int flags)
{
    int bytesReceived = OE_SOCKET_ERROR;
    sgx_status_t sgxStatus;
    recv_Result result;

    result.bytesReceived = 0;

    sgxStatus = ocall_recv(&result, s, len, flags);
    if ((sgxStatus != SGX_SUCCESS) || (result.bytesReceived > len))
    {
        result.error = OE_ENETDOWN;
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
            result.error = OE_ENETDOWN;
        }
    }
    oe_wsa_set_last_error(result.error);
    bytesReceived = (result.error != 0) ? OE_SOCKET_ERROR : result.bytesReceived;
    return bytesReceived;
}

int
oe_send(
    _In_ oe_socket_t s,
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
        result.error = OE_ENETDOWN;
        result.bytesSent = 0;
    }
    else
    {
        sgxStatus = ocall_send(&result, s, hReeBuffer, flags);

        TcpsFreeReeBuffer(hReeBuffer);

        if (sgxStatus != SGX_SUCCESS)
        {
            result.error = OE_ENETDOWN;
            result.bytesSent = 0;
        }
    }
    oe_wsa_set_last_error(result.error);
    return (result.error != 0) ? OE_SOCKET_ERROR : result.bytesSent;
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
oe_ntohl(
    _In_ uint32_t netLong)
{
    return swap_uint32(netLong);
}

uint16_t
oe_ntohs(
    _In_ uint16_t netShort)
{
    return swap_uint16(netShort);
}

uint32_t
oe_htonl(
    _In_ uint32_t hostLong)
{
    return swap_uint32(hostLong);
}

uint16_t
oe_htons(
    _In_ uint16_t hostShort)
{
    return swap_uint16(hostShort);
}

int
oe_setsockopt(
    _In_ oe_socket_t s,
    _In_ int level,
    _In_ int optname,
    _In_reads_bytes_(optlen) const char* optval,
    _In_ int optlen)
{
    oe_socket_error_t socketError = 0;
    sgx_status_t sgxStatus;

    sgxStatus = ocall_setsockopt(&socketError, s, level, optname, optval, optlen);
    if (sgxStatus != SGX_SUCCESS) {
        socketError = OE_ENETDOWN;
    }
    oe_wsa_set_last_error(socketError);
    return (socketError == 0) ? 0 : OE_SOCKET_ERROR;
}

int
oe_ioctlsocket(
    _In_ oe_socket_t s,
    _In_ long cmd,
    _Inout_ u_long *argp)
{
    ioctlsocket_Result result = {0};
    sgx_status_t sgxStatus;

    sgxStatus = ocall_ioctlsocket(&result, s, cmd, *argp);
    if (sgxStatus != SGX_SUCCESS) {
        result.error = OE_ENETDOWN;
    }
    oe_wsa_set_last_error(result.error);
    *argp = result.outputValue;
    return (result.error == 0) ? 0 : OE_SOCKET_ERROR;
}

int
oe_connect(
    _In_ oe_socket_t s,
    _In_reads_bytes_(namelen) const oe_sockaddr *name,
    _In_ int namelen)
{
    oe_socket_error_t socketError = 0;
    sgx_status_t sgxStatus;

    sgxStatus = ocall_connect(&socketError, s, name, namelen);
    if (sgxStatus != SGX_SUCCESS) {
        socketError = OE_ENETDOWN;
    }
    oe_wsa_set_last_error(socketError);
    return (socketError == 0) ? 0 : OE_SOCKET_ERROR;
}

oe_socket_t
oe_accept(
    _In_ oe_socket_t a_Socket,
    _Out_writes_bytes_(*addrlen) struct sockaddr* a_SockAddr,
    _Inout_ int *a_pAddrLen)
{
    accept_Result result;
    int addrlen = (a_pAddrLen != NULL) ? *a_pAddrLen : 0;
    sgx_status_t sgxStatus = ocall_accept(&result, a_Socket, addrlen);
    if ((sgxStatus != SGX_SUCCESS) || (result.addrlen > addrlen)) {
        result.error = OE_ENETDOWN;
        addrlen = 0;
    } else {
        memcpy(a_SockAddr, result.addr, result.addrlen);
        addrlen = result.addrlen;
    }
    oe_wsa_set_last_error(result.error);
    if (a_pAddrLen != NULL) {
        *a_pAddrLen = addrlen;
    }
    return (result.error == 0) ? result.hNewSocket : OE_INVALID_SOCKET;
}

int
oe_getpeername(
    _In_ oe_socket_t s,
    _Out_writes_bytes_(*addrlen) struct sockaddr* addr,
    _Inout_ int *addrlen)
{
    GetSockName_Result result;
    sgx_status_t sgxStatus = ocall_getpeername(&result, s, *addrlen);
    if ((sgxStatus != SGX_SUCCESS) || (result.addrlen > *addrlen)) {
        result.error = OE_ENETDOWN;
        *addrlen = 0;
    } else {
        memcpy(addr, result.addr, result.addrlen);
        *addrlen = result.addrlen;
    }
    oe_wsa_set_last_error(result.error);
    return (result.error == 0) ? 0 : OE_SOCKET_ERROR;
}

int
oe_getsockname(
    _In_ oe_socket_t s,
    _Out_writes_bytes_(*addrlen) struct sockaddr* addr,
    _Inout_ int *addrlen)
{
    GetSockName_Result result;
    sgx_status_t sgxStatus = ocall_getsockname(&result, s, *addrlen);
    if ((sgxStatus != SGX_SUCCESS) || (result.addrlen > *addrlen)) {
        result.error = OE_ENETDOWN;
        *addrlen = 0;
    } else {
        memcpy(addr, result.addr, result.addrlen);
        *addrlen = result.addrlen;
    }
    oe_wsa_set_last_error(result.error);
    return (result.error == 0) ? 0 : OE_SOCKET_ERROR;
}

int
oe_bind(
    _In_ oe_socket_t s,
    _In_reads_bytes_(namelen) const oe_sockaddr *name,
    _In_ int namelen)
{
    oe_socket_error_t socketError = 0;
    sgx_status_t sgxStatus;

    sgxStatus = ocall_bind(&socketError, s, name, namelen);
    if (sgxStatus != SGX_SUCCESS) {
        socketError = OE_ENETDOWN;
    }
    oe_wsa_set_last_error(socketError);
    return (socketError == 0) ? 0 : OE_SOCKET_ERROR;
}

uint32_t
oe_inet_addr(
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
oe_freeaddrinfo(
    _In_ oe_addrinfo* ailist)
{
    oe_addrinfo* ai;
    oe_addrinfo* next;

    for (ai = ailist; ai != NULL; ai = next) {
        next = ai->ai_next;
        if (ai->ai_canonname != NULL) {
            oe_free(ai->ai_canonname);
        }
        if (ai->ai_addr != NULL) {
            oe_free(ai->ai_addr);
        }
        oe_free(ai);
        ailist = next;
    }
}

int
oe_getaddrinfo(
    _In_z_ const char* pNodeName,
    _In_z_ const char* pServiceName,
    _In_ const oe_addrinfo* pHints,
    _Out_ oe_addrinfo** ppResult)
{
    int bytesReceived = OE_SOCKET_ERROR;
    sgx_status_t sgxStatus;
    getaddrinfo_Result result;
    oe_addrinfo* ailist = NULL;
    oe_addrinfo* ai;
    oe_addrinfo** pNext = &ailist;
    Tcps_StatusCode uStatus = Tcps_Good;

    result.addressCount = 0;

    sgxStatus = ocall_getaddrinfo(
        &result,
        (char*)pNodeName,
        (char*)pServiceName,
        (pHints != NULL) ? pHints->ai_flags : 0,
        (pHints != NULL) ? pHints->ai_family : 0,
        (pHints != NULL) ? pHints->ai_socktype : 0,
        (pHints != NULL) ? pHints->ai_protocol : 0);
    if (sgxStatus != SGX_SUCCESS) {
        result.error = OE_ENOTRECOVERABLE;
    }

    if (result.addressCount > 0) {
        int bytesReceived = result.addressCount * sizeof(addrinfo_Buffer);
        char* buf = oe_malloc(bytesReceived);
        if (buf == NULL) {
            uStatus = Tcps_BadOutOfMemory;
            result.error = OE_ENOMEM;
        } else {
            uStatus = TcpsPullDataFromReeBuffer(
                result.hMessage,
                buf,
                bytesReceived);
            if (Tcps_IsBad(uStatus))
            {
                result.error = OE_ENOTRECOVERABLE;
            }
        }

        TcpsFreeReeBuffer(result.hMessage);

        struct addrinfo_Buffer* response = (struct addrinfo_Buffer*)buf;

        /* We now have a response to deserialize. */
        for (int i = 0; i < result.addressCount; i++) {
            if (response[i].ai_addrlen > sizeof(oe_sockaddr_storage) ||
                response[i].ai_addrlen > sizeof(response[i].ai_addr)) {
                result.error = OE_ENOMEM;
                break;
            }
            ai = oe_malloc(sizeof(*ai));
            if (ai == NULL) {
                result.error = OE_ENOMEM;
                break;
            }
            ai->ai_addr = oe_malloc(response[i].ai_addrlen);
            if (ai->ai_addr == NULL) {
                oe_free(ai);
                result.error = OE_ENOMEM;
                break;
            }
            memcpy(ai->ai_addr, response[i].ai_addr, response[i].ai_addrlen);

            ai->ai_flags = response[i].ai_flags;
            ai->ai_family = response[i].ai_family;
            ai->ai_socktype = response[i].ai_socktype;
            ai->ai_protocol = response[i].ai_protocol;
            ai->ai_addrlen = response[i].ai_addrlen;
            if (response[i].ai_canonname[0] != 0) {
                ai->ai_canonname = oe_malloc(sizeof(response[i].ai_canonname) + 1);
                if (ai->ai_canonname == NULL) {
                    oe_free(ai);
                    result.error = OE_ENOMEM;
                    break;
                }
                strncpy(ai->ai_canonname, response[i].ai_canonname,
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
oe_getnameinfo(
    _In_ const struct oe_sockaddr *sa,
    _In_ oe_socklen_t salen,
    _Out_writes_opt_z_(hostlen) char* host,
    _In_ size_t hostlen,
    _Out_writes_opt_z_(servlen) char* serv,
    _In_ size_t servlen,
    _In_ int flags)
{
    getnameinfo_Result result = { 0 };
    sgx_status_t sgxStatus;

    sgxStatus = ocall_getnameinfo(&result, sa, salen, flags);
    if (sgxStatus != SGX_SUCCESS) {
        result.error = OE_ENOTRECOVERABLE;
    }

    if (host != NULL) {
        strncpy(host, result.host, hostlen);
        host[hostlen - 1] = 0;
    }

    if (serv != NULL) {
        strncpy(serv, result.serv, servlen);
        serv[servlen - 1] = 0;
    }

    return result.error;
}
