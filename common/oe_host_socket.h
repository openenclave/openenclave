// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_SOCKET_H
#define _OE_HOST_SOCKET_H

#include <openenclave/corelibc/bits/types.h>
#include <openenclave/internal/syscall/types.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

#define GETADDRINFO_HANDLE_MAGIC 0xed11d13a

typedef struct _getaddrinfo_handle
{
    uint32_t magic;
    struct addrinfo* res;
    struct addrinfo* next;
} getaddrinfo_handle_t;

int _getaddrinfo_open_ocall(
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    uint64_t* handle_out);

int _getaddrinfo_read_ocall(
    uint64_t handle_,
    int* ai_flags,
    int* ai_family,
    int* ai_socktype,
    int* ai_protocol,
    oe_socklen_t ai_addrlen_in,
    oe_socklen_t* ai_addrlen,
    struct oe_sockaddr* ai_addr,
    size_t ai_canonnamelen_in,
    size_t* ai_canonnamelen,
    char* ai_canonname);

int _getaddrinfo_close_ocall(uint64_t handle_);

#endif // _OE_HOST_SOCKET_H
