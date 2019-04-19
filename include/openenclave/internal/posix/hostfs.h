// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
**==============================================================================
**
** host_socket.h
**
**     Definition of the host_socket internal types and data
**
**==============================================================================
*/

#ifndef _OE_INTERNAL_HOSTFS_H
#define _OE_INTERNAL_HOSTFS_H

#include <openenclave/internal/posix/device.h>

OE_EXTERNC_BEGIN

oe_device_t* oe_get_hostfs_device(void);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_HOSTFS_H */
