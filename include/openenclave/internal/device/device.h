// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_POSIX_DEVICE_H
#define _OE_POSIX_DEVICE_H

#include <openenclave/bits/device.h>
#include <openenclave/bits/result.h>
#include <openenclave/internal/device/epollops.h>
#include <openenclave/internal/device/eventfdops.h>
#include <openenclave/internal/device/fsops.h>
#include <openenclave/internal/device/posix.h>
#include <openenclave/internal/device/sockops.h>

OE_EXTERNC_BEGIN

typedef enum _oe_device_type
{
    OE_DEVICE_TYPE_NONE = 0,
    OE_DEVICE_TYPE_FILESYSTEM,
    OE_DEVICE_TYPE_DIRECTORY,
    OE_DEVICE_TYPE_FILE,
    OE_DEVICE_TYPE_SOCKET,
    OE_DEVICE_TYPE_EPOLL,
    OE_DEVICE_TYPE_EVENTFD
} oe_device_type_t;

typedef struct _oe_device oe_device_t;

struct _oe_device
{
    /* Type of this device. */
    oe_device_type_t type;

    /* String name of this device. */
    const char* name;

    /* Index of the device into the device table. */
    uint64_t devid;

    union {
        oe_device_ops_t* base;
        oe_fs_ops_t* fs;
        oe_sock_ops_t* socket;
        oe_epoll_ops_t* epoll;
        oe_eventfd_ops_t* eventfd;
    } ops;
};

uint64_t oe_allocate_devid(uint64_t devid);

int oe_release_devid(uint64_t devid);

int oe_set_device(uint64_t devid, oe_device_t* pdevice);

oe_device_t* oe_get_device(uint64_t devid, oe_device_type_t type);

/* Find the device with the given name and type. */
oe_device_t* oe_find_device(const char* name, oe_device_type_t type);

int oe_remove_device(uint64_t devid);

OE_EXTERNC_END

#endif // _OE_POSIX_DEVICE_H
