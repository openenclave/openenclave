// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_POSIX_FD_H
#define _OE_POSIX_FD_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include "device.h"

OE_EXTERNC_BEGIN

typedef struct _oe_device oe_device_t;

oe_device_t* oe_set_fd_device(int fd, oe_device_t* device);

oe_device_t* oe_get_fd_device(int fd, oe_device_type_t type);

int oe_release_fd(int fd);

int oe_assign_fd_device(oe_device_t* device);

OE_EXTERNC_END

#endif // _OE_POSIX_FD_H
