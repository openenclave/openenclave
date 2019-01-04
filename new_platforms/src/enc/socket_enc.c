/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <openenclave/enclave.h>
#include "enclavelibc.h"
#include "tcps_string_t.h"
#include <stdlib.h>

typedef struct {
    intptr_t provider_socket;
    const oe_socket_provider_t* provider;
} oe_internal_socket_t;

oe_socket_t oe_register_socket(
    const oe_socket_provider_t* provider,
    intptr_t provider_socket)
{
    oe_internal_socket_t* s = (oe_internal_socket_t*)malloc(sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    s->provider = provider;
    s->provider_socket = provider_socket;
    return s;
}

void ecall_InitializeSockets() {}

static int
fill_internal_fd_set(
    _Out_ oe_provider_fd_set* provider_fds,
    _In_opt_ const oe_fd_set* fds,
    _Inout_ const oe_socket_provider_t** provider)
{
    unsigned int i;
    memset(provider_fds, 0, sizeof(*provider_fds));
    if (fds == NULL) {
        return 0;
    }

    provider_fds->fd_count = fds->fd_count;
    for (i = 0; i < fds->fd_count; i++) {
        oe_internal_socket_t* internal_socket = (oe_internal_socket_t*)fds->fd_array[i];
        if (internal_socket == NULL) {
            continue;
        }
        if (*provider == NULL) {
            *provider = internal_socket->provider;
        } else if (*provider != internal_socket->provider) {
            /* We currently only support select() among sockets from the same provider. */
            return -1;
        }
        provider_fds->fd_array[i] = internal_socket->provider_socket; 
    }
    return 0;
}

static void
set_fd_set_results(
    _In_ const oe_provider_fd_set* provider_fds,
    _Inout_opt_ oe_fd_set* fds)
{
    unsigned int i;
    if (fds == NULL) {
        return;
    }
    for (i = 0; i < provider_fds->fd_count; i++) {
        if (provider_fds->fd_array[i] == 0) {
            fds->fd_array[i] = NULL;
        }
    }
}

int
oe_select(
    int a_nFds,
    _Inout_opt_ oe_fd_set* a_readfds,
    _Inout_opt_ oe_fd_set* a_writefds,
    _Inout_opt_ oe_fd_set* a_exceptfds,
    _In_opt_ const struct timeval* a_Timeout)
{
    const oe_socket_provider_t* provider = NULL;
    oe_provider_fd_set provider_readfds;
    oe_provider_fd_set provider_writefds;
    oe_provider_fd_set provider_exceptfds;

    if (fill_internal_fd_set(&provider_readfds, a_readfds, &provider) < 0) {
        return -1;
    }
    if (fill_internal_fd_set(&provider_writefds, a_writefds, &provider) < 0) {
        return -1;
    }
    if (fill_internal_fd_set(&provider_exceptfds, a_exceptfds, &provider) < 0) {
        return -1;
    }

    int result = provider->s_select(
        a_nFds,
        (provider_readfds.fd_count == 0) ? NULL : &provider_readfds,
        (provider_writefds.fd_count == 0) ? NULL : &provider_writefds,
        (provider_exceptfds.fd_count == 0) ? NULL : &provider_exceptfds,
        a_Timeout);

    if (result == 0) {
        set_fd_set_results(&provider_readfds, a_readfds);
        set_fd_set_results(&provider_writefds, a_writefds);
        set_fd_set_results(&provider_exceptfds, a_exceptfds);
    }

    return result;
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
oe_shutdown(
    _In_ oe_socket_t s,
    int how)
{
    oe_internal_socket_t* internal_socket = (oe_internal_socket_t*)s;
    return internal_socket->provider->s_shutdown(internal_socket->provider_socket, how);
}

int
oe_closesocket(
    _In_ oe_socket_t s)
{
    oe_internal_socket_t* internal_socket = (oe_internal_socket_t*)s;
    int result = internal_socket->provider->s_close(internal_socket->provider_socket);
    free(internal_socket);
    return result;
}

int
oe_listen(
    _In_ oe_socket_t s,
    int backlog)
{
    oe_internal_socket_t* internal_socket = (oe_internal_socket_t*)s;
    return internal_socket->provider->s_listen(internal_socket->provider_socket, backlog);
}

int
oe_getsockopt(
    _In_ oe_socket_t s,
    int level,
    int optname,
    _Out_writes_(*optlen) char *optval,
    _Inout_ socklen_t *optlen)
{
    oe_internal_socket_t* internal_socket = (oe_internal_socket_t*)s;
    return internal_socket->provider->s_getsockopt(internal_socket->provider_socket, level, optname, optval, optlen);
}

ssize_t
oe_recv(
    _In_ oe_socket_t s,
    _Out_writes_(len) void *buf,
    size_t len,
    int flags)
{
    oe_internal_socket_t* internal_socket = (oe_internal_socket_t*)s;
    return internal_socket->provider->s_recv(internal_socket->provider_socket, buf, len, flags);
}

int
oe_send(
    _In_ oe_socket_t s,
    _In_reads_bytes_(len) const char *buf,
    int len,
    int flags)
{
    oe_internal_socket_t* internal_socket = (oe_internal_socket_t*)s;
    return internal_socket->provider->s_send(internal_socket->provider_socket, buf, len, flags);
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
    uint32_t netLong)
{
    return swap_uint32(netLong);
}

uint16_t
oe_ntohs(
    uint16_t netShort)
{
    return swap_uint16(netShort);
}

uint32_t
oe_htonl(
    uint32_t hostLong)
{
    return swap_uint32(hostLong);
}

uint16_t
oe_htons(
    uint16_t hostShort)
{
    return swap_uint16(hostShort);
}

int
oe_setsockopt(
    _In_ oe_socket_t s,
    int level,
    int optname,
    _In_reads_bytes_(optlen) const char* optval,
    socklen_t optlen)
{
    oe_internal_socket_t* internal_socket = (oe_internal_socket_t*)s;
    return internal_socket->provider->s_setsockopt(internal_socket->provider_socket, level, optname, optval, optlen);
}

int
oe_ioctlsocket(
    _In_ oe_socket_t s,
    long cmd,
    _Inout_ u_long *argp)
{
    oe_internal_socket_t* internal_socket = (oe_internal_socket_t*)s;
    return internal_socket->provider->s_ioctl(internal_socket->provider_socket, cmd, argp);
}

int
oe_connect(
    _In_ oe_socket_t s,
    _In_reads_bytes_(namelen) const oe_sockaddr *name,
    int namelen)
{
    oe_internal_socket_t* internal_socket = (oe_internal_socket_t*)s;
    return internal_socket->provider->s_connect(internal_socket->provider_socket, name, namelen);
}

oe_socket_t
oe_accept(
    _In_ oe_socket_t s,
    _Out_writes_bytes_(*addrlen) struct sockaddr* addr,
    _Inout_ int *addrlen)
{
    oe_internal_socket_t* new_internal_socket = (oe_internal_socket_t*)malloc(sizeof(*new_internal_socket));
    if (new_internal_socket == (intptr_t)NULL) {
    }
    oe_internal_socket_t* internal_socket = (oe_internal_socket_t*)s;
    intptr_t new_provider_socket = internal_socket->provider->s_accept(internal_socket->provider_socket, addr, addrlen);
    if (new_provider_socket == (intptr_t)NULL) {
        free(new_internal_socket);
        return OE_INVALID_SOCKET;
    }
    new_internal_socket->provider = internal_socket->provider;
    new_internal_socket->provider_socket = new_provider_socket;
    return new_internal_socket;
}

int
oe_getpeername(
    _In_ oe_socket_t s,
    _Out_writes_bytes_(*addrlen) struct sockaddr* addr,
    _Inout_ int *addrlen)
{
    oe_internal_socket_t* internal_socket = (oe_internal_socket_t*)s;
    return internal_socket->provider->s_getpeername(internal_socket->provider_socket, addr, addrlen);
}

int
oe_getsockname(
    _In_ oe_socket_t s,
    _Out_writes_bytes_(*addrlen) struct sockaddr* addr,
    _Inout_ int *addrlen)
{
    oe_internal_socket_t* internal_socket = (oe_internal_socket_t*)s;
    return internal_socket->provider->s_getsockname(internal_socket->provider_socket, addr, addrlen);
}

int
oe_bind(
    _In_ oe_socket_t s,
    _In_reads_bytes_(addrlen) const oe_sockaddr *addr,
    int addrlen)
{
    oe_internal_socket_t* internal_socket = (oe_internal_socket_t*)s;
    return internal_socket->provider->s_bind(internal_socket->provider_socket, addr, addrlen);
}

uint32_t
oe_inet_addr(
    _In_z_ const char *cp)
{
    /* We only support dotted decimal. */
    uint32_t value;
    uint8_t* byte = (uint8_t*)&value;
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
    return value;
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
