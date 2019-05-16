// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_POSIX_EPOLLOPS_H
#define _OE_POSIX_EPOLLOPS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/sys/epoll.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/posix/deviceops.h>

OE_EXTERNC_BEGIN

struct oe_epoll_event;
struct oe_pollfd;
typedef struct _oe_device oe_device_t;
typedef struct _oe_fd oe_fd_t;

typedef struct _oe_epoll_device_ops
{
    oe_device_ops_t base;

    oe_fd_t* (*epoll_create)(oe_device_t* epfd_device, int size);

    oe_fd_t* (*epoll_create1)(oe_device_t* epfd_device, int flags);

} oe_epoll_device_ops_t;

OE_EXTERNC_END

#endif /* _OE_POSIX_EPOLLOPS_H */
