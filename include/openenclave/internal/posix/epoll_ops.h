// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNA_POSIX_EPOLL_OPS_H
#define _OE_INTERNA_POSIX_EPOLL_OPS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/posix/device_ops.h>

OE_EXTERNC_BEGIN

struct oe_epoll_event;
struct oe_pollfd;
typedef struct _oe_device oe_device_t;

typedef struct _oe_epoll_ops
{
    oe_device_ops_t base;

    oe_device_t* (*create)(oe_device_t* epoll_device, int size);

    oe_device_t* (*create1)(oe_device_t* epoll_device, int flags);

    int (*ctl_add)(int epoll_fd, int enclave_fd, struct oe_epoll_event* event);

    int (*ctl_del)(int epoll_fd, int enclave_fd);

    int (*ctl_mod)(int epoll_fd, int enclave_fd, struct oe_epoll_event* event);

    int (*wait)(
        int epoll_fd,
        struct oe_epoll_event* events,
        size_t maxevents,
        int64_t timeout);

    int (*poll)(
        int epoll_fd,
        struct oe_pollfd* events,
        size_t maxevents,
        int64_t timeout);

    int (*addeventdata)(
        int epoll_fd,
        int enclave_fd,
        uint32_t events,
        uint64_t data);

    uint64_t (*geteventdata)(oe_device_t* epoll_device, uint32_t list_idx);

} oe_epoll_ops_t;

OE_EXTERNC_END

#endif /* _OE_INTERNA_POSIX_EPOLL_OPS_H */
