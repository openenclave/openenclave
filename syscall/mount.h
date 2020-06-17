// Copyright (c) Open Enclave SDK contributors._ops
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_MOUNT_H
#define _OE_SYSCALL_MOUNT_H

#include <openenclave/bits/defs.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/internal/syscall/device.h>

OE_EXTERNC_BEGIN

/* Use mounter to resolve this path to a target path. */
oe_device_t* oe_mount_resolve(const char* path, char suffix[OE_PATH_MAX]);

OE_EXTERNC_END

#endif // _OE_SYSCALL_MOUNT_H
