// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SOCK_OPS_H
#define _OE_SOCK_OPS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/device_ops.h>

OE_EXTERNC_BEGIN

typedef uint32_t socklen_t;
struct oe_sockaddr;
struct oe_addrinfo;

typedef struct _oe_sock_ops
{
    oe_device_ops_t base;

    oe_device_t* (
        *socket)(oe_device_t* dev, int domain, int type, int protocol);

    int (*connect)(
        oe_device_t* dev,
        const struct oe_sockaddr* addr,
        socklen_t addrlen);
    int (*accept)(
        oe_device_t* dev,
        struct oe_sockaddr* addr,
        socklen_t* addrlen);
    int (*bind)(
        oe_device_t* dev,
        const struct oe_sockaddr* addr,
        socklen_t addrlen);

    int (*listen)(oe_device_t* dev, int backlog);

    ssize_t (*recv)(oe_device_t* dev, void* buf, size_t len, int flags);
    ssize_t (*send)(oe_device_t* dev, const void* buf, size_t len, int flags);

    int (*shutdown)(oe_device_t* dev, int how);
    int (*getsockopt)(
        oe_device_t* dev,
        int level,
        int optname,
        void* optval,
        socklen_t* optlen);
    int (*setsockopt)(
        oe_device_t* dev,
        int level,
        int optname,
        const void* optval,
        socklen_t optlen);
    int (*getpeername)(
        oe_device_t* dev,
        struct oe_sockaddr* addr,
        socklen_t* addrlen);
    int (*getsockname)(
        oe_device_t* dev,
        struct oe_sockaddr* addr,
        socklen_t* addrlen);

#if 0
    int (*getaddrinfo)( oe_device_t* dev, const char *node, const char *service, const struct oe_addrinfo *hints, struct oe_addrinfo **res);

    void (*freeaddrinfo)( oe_device_t* dev, struct oe_addrinfo *res);
    int (*gethostname)( oe_device_t* dev, char *name, size_t len);

    int (*getnameinfo)( oe_device_t* dev, const struct oe_sockaddr *sa, socklen_t salen, char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags);
#endif
} oe_sock_ops_t;

/* ATTN: where does select go? */

OE_EXTERNC_END

#endif // _OE_SOCK_OPS_H
