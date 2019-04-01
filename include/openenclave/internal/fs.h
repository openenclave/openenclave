// Copyright (c) Microsoft Corporation. All rights reserved._ops
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_FS_H
#define _OE_INTERNAL_FS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/dirent.h>
#include <openenclave/corelibc/fcntl.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/sys/mount.h>
#include <openenclave/corelibc/sys/stat.h>
#include <openenclave/corelibc/sys/uio.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/device.h>

OE_EXTERNC_BEGIN

/* Get the access mode from the open() flags. */
OE_INLINE int oe_get_open_access_mode(int flags)
{
    return (flags & 000000003);
}

/* The enclave calls this to get an instance of host file system (SGXFS). */
oe_device_t* oe_fs_get_sgxfs(void);

int oe_register_sgxfs_device(void);

/* Initialize the stdin, stdout, and stderr devices. */
int oe_initialize_console_devices(void);

/* Use mounter to resolve this path to a target path. */
oe_device_t* oe_mount_resolve(const char* path, char suffix[OE_PATH_MAX]);

OE_EXTERNC_END

#endif // _OE_INTERNAL_FS_H
