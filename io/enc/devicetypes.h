// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_POSIX_DEVICETYPES_H
#define _OE_INTERNAL_POSIX_DEVICETYPES_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

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

OE_EXTERNC_END

#endif // _OE_INTERNAL_POSIX_DEVICETYPES_H
