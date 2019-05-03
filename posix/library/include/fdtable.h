// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_POSIX_FDTABLE_H
#define _OE_POSIX_FDTABLE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include "device.h"

OE_EXTERNC_BEGIN

int oe_fdtable_set(int fd, oe_device_t* device);

oe_device_t* oe_fdtable_get(int fd, oe_device_type_t type);

int oe_fdtable_clear(int fd);

int oe_fdtable_assign(oe_device_t* device);

OE_EXTERNC_END

#endif // _OE_POSIX_FDTABLE_H
