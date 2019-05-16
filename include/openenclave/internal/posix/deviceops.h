// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_POSIX_DEVICEOPS_H
#define _OE_POSIX_DEVICEOPS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/posix/types.h>
#include <openenclave/internal/types.h>

OE_EXTERNC_BEGIN

typedef struct _oe_device oe_device_t;

typedef struct _oe_device_ops
{
    int (*dup)(oe_device_t* device, oe_device_t** new_device);

    int (*release)(oe_device_t* dev);

    oe_host_fd_t (*get_host_fd)(oe_device_t* device);

    ssize_t (*read)(oe_device_t* dev, void* buf, size_t count);

    ssize_t (*write)(oe_device_t* dev, const void* buf, size_t count);

    int (*close)(oe_device_t* dev);

    int (*ioctl)(oe_device_t* dev, unsigned long request, uint64_t arg);

    int (*fcntl)(oe_device_t* dev, int cmd, uint64_t arg);

} oe_device_ops_t;

OE_EXTERNC_END

#endif // _OE_POSIX_DEVICEOPS_H
