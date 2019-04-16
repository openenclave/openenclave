// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYS_MOUNT_H
#define _OE_SYS_MOUNT_H

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

#if defined(OE_NEED_STDC_NAMES)

#define MS_RDONLY OE_MS_RDONLY

OE_INLINE int mount(
    const char* source,
    const char* target,
    const char* filesystemtype,
    unsigned long mountflags,
    const void* data)
{
    return oe_mount(source, target, filesystemtype, mountflags, data);
}

OE_INLINE int umount(const char* target)
{
    return oe_umount(target);
}

OE_INLINE int umount2(const char* target, int flags)
{
    return oe_umount2(target, flags);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_SYS_MOUNT_H */
