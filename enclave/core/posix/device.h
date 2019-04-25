// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_POSIX_DEVICE_H
#define _OE_INTERNAL_POSIX_DEVICE_H

#include <openenclave/bits/device.h>
#include <openenclave/bits/result.h>
#include "devicetypes.h"
#include "devid.h"
#include "epoll_ops.h"
#include "eventfd_ops.h"
#include "fd.h"
#include "fs_ops.h"
#include "sock_ops.h"

OE_EXTERNC_BEGIN

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

int oe_set_devid_device(uint64_t devid, oe_device_t* pdevice);

oe_device_t* oe_get_devid_device(uint64_t devid);

uint64_t oe_device_name_to_devid(const char* name);

int oe_remove_device(uint64_t devid);

OE_EXTERNC_END

#endif // _OE_INTERNAL_POSIX_DEVICE_H
