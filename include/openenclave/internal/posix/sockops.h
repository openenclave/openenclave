// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_POSIX_SOCKOPS_H
#define _OE_POSIX_SOCKOPS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include "deviceops.h"

OE_EXTERNC_BEGIN

typedef uint32_t socklen_t;
struct oe_sockaddr;
struct oe_addrinfo;
struct oe_msghdr;

// clang-format off
typedef struct _oe_sock_ops
{
    oe_device_ops_t base;

    oe_device_t* (*socket)(
        oe_device_t* dev,
        int domain,
        int type,
        int protocol);

    int (*connect)(
        oe_device_t* dev,
        const struct oe_sockaddr* addr,
        socklen_t addrlen);

    oe_device_t* (*accept)(
        oe_device_t* dev,
        struct oe_sockaddr* addr,
        socklen_t* addrlen);

    int (*bind)(
        oe_device_t* dev,
        const struct oe_sockaddr* addr,
        socklen_t addrlen);

    int (*listen)(
        oe_device_t* dev,
        int backlog);

    ssize_t (*recv)(
        oe_device_t* dev,
        void* buf,
        size_t len,
        int flags);

    ssize_t (*recvfrom)(
        oe_device_t* dev,
        void* buf,
        size_t len,
        int flags,
        const struct oe_sockaddr* src_addr,
        socklen_t* addrlen);

    ssize_t (*send)(
        oe_device_t* dev,
        const void* buf,
        size_t len,
        int flags);

    ssize_t (*sendto)(
        oe_device_t* dev,
        const void* buf,
        size_t len,
        int flags,
        const struct oe_sockaddr* dest_addr,
        socklen_t addrlen);

    ssize_t (*socketpair)(
        oe_device_t* dev,
        int domain,
        int type,
        int protocol,
        oe_device_t* retdevs[2]);

    ssize_t (*sendmsg)(
        oe_device_t* dev,
        const struct oe_msghdr* msg,
        int flags);

    ssize_t (*recvmsg)(
        oe_device_t* dev,
        struct oe_msghdr* msg,
        int flags);

    int (*shutdown)(
        oe_device_t* dev,
        int how);

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

} oe_sock_ops_t;
// clang-format on

OE_EXTERNC_END

#endif // _OE_POSIX_SOCKOPS_H
