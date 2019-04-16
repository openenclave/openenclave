// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_DEVICETYPES_H
#define _OE_DEVICETYPES_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef enum _oe_device_type
{
    OE_DEVICE_TYPE_NONE = 0,

    OE_DEVICETYPE_FILESYSTEM,

    // This entry describes a file in the hosts's file system
    OE_DEVICETYPE_DIRECTORY,

    // This entry describes an internet socket
    OE_DEVICETYPE_FILE,

    // This entry describes an enclave to enclave
    OE_DEVICETYPE_SOCKET,

    // This entry describes an epoll device
    OE_DEVICETYPE_EPOLL,

    // This entry describes an eventfd device
    OE_DEVICETYPE_EVENTFD
} oe_device_type_t;

OE_EXTERNC_END

#endif // _OE_DEVICETYPES_H
