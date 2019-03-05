
/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef __OE_EPOLL_OPS_H__
#define __OE_EPOLL_OPS_H__

#include <openenclave/internal/device_ops.h>

#ifdef cplusplus
extern "C"
{
#endif

    struct oe_epoll_event;

    typedef struct _oe_device oe_device_t;

    typedef struct _oe_epoll_ops
    {
        oe_device_ops_t base;
        oe_device_t* (*create)(oe_device_t* epoll_device, int size);
        oe_device_t* (*create1)(oe_device_t* epoll_device, int flags);
        int (*ctl_add)(
            int epoll_fd,
            int enclave_fd,
            struct oe_epoll_event* event);
        int (*ctl_del)(int epoll_fd, int enclave_fd);
        int (*ctl_mod)(
            int epoll_fd,
            int enclave_fd,
            struct oe_epoll_event* event);
        int (*wait)(
            int epoll_fd,
            struct oe_epoll_event* events,
            size_t maxevents,
            int64_t timeout);

        uint64_t (*geteventdata)(oe_device_t* epoll_device, uint32_t list_idx);

    } oe_epoll_ops_t;

#ifdef cplusplus
}
#endif

#endif
