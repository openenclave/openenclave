// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_SYS_MOUNT_H
#define _OE_SYSCALL_SYS_MOUNT_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

#define OE_MS_RDONLY 1

int oe_mount(
    const char* source,
    const char* target,
    const char* filesystemtype,
    unsigned long mountflags,
    const void* data);

int oe_umount(const char* target);

int oe_umount2(const char* target, int flags);

OE_EXTERNC_END

#endif /* _OE_SYSCALL_SYS_MOUNT_H */
