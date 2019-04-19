// Copyright (c) Microsoft Corporation. All rights reserved._ops
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_POSIX_MOUNT_H
#define _OE_INTERNAL_POSIX_MOUNT_H

#include <openenclave/bits/defs.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/internal/posix/device.h>

OE_EXTERNC_BEGIN

/* Use mounter to resolve this path to a target path. */
oe_device_t* oe_mount_resolve(const char* path, char suffix[OE_PATH_MAX]);

OE_EXTERNC_END

#endif // _OE_INTERNAL_POSIX_MOUNT_H
