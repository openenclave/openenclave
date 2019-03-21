// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_DEVICE_OPS_H
#define _OE_DEVICE_OPS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/stdarg.h>
#include <openenclave/internal/types.h>

OE_EXTERNC_BEGIN

typedef struct _oe_device oe_device_t;

typedef struct _oe_device_ops
{
    int (*clone)(oe_device_t* device, oe_device_t** new_device);

    int (*dup)(oe_device_t* device, oe_device_t** new_device);

    int (*shutdown)(oe_device_t* pthis);

    int (*release)(oe_device_t* device);

    int (*notify)(oe_device_t* device, uint64_t notfication_mask);

    ssize_t (*get_host_fd)(oe_device_t* device);

    uint64_t (*ready_state)(oe_device_t* device);

    ssize_t (*read)(oe_device_t* file, void* buf, size_t count);

    ssize_t (*write)(oe_device_t* file, const void* buf, size_t count);

    int (*close)(oe_device_t* file);

    int (*ioctl)(oe_device_t* file, unsigned long request, oe_va_list ap);

} oe_device_ops_t;

OE_EXTERNC_END

#endif // _OE_DEVICE_OPS_H
