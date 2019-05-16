// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_POSIX_SOCKOPS_H
#define _OE_POSIX_SOCKOPS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include "deviceops.h"

OE_EXTERNC_BEGIN

typedef uint32_t socklen_t;
typedef struct _oe_fd oe_fd_t;
struct oe_sockaddr;
struct oe_addrinfo;
struct oe_msghdr;

// clang-format off
typedef struct _oe_sock_device_ops
{
    oe_device_ops_t base;

    oe_fd_t* (*socket)(
        oe_device_t* dev,
        int domain,
        int type,
        int protocol);

    ssize_t (*socketpair)(
        oe_device_t* dev,
        int domain,
        int type,
        int protocol,
        oe_fd_t* retdevs[2]);

} oe_sock_device_ops_t;
// clang-format on

OE_EXTERNC_END

#endif // _OE_POSIX_SOCKOPS_H
