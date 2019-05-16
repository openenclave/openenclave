// Copyright (c) Microsoft Corporation. All rights reserved._ops
// Licensed under the MIT License.

#ifndef _OE_POSIX_FSOPS_H
#define _OE_POSIX_FSOPS_H

#include <openenclave/bits/types.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/sys/mount.h>
#include <openenclave/corelibc/sys/stat.h>
#include "deviceops.h"

OE_EXTERNC_BEGIN

typedef struct _oe_file oe_file_t;
typedef struct _oe_fs_device_ops oe_fs_device_ops_t;
typedef struct _oe_device oe_device_t;
typedef struct _oe_fd oe_fd_t;
struct oe_stat;

struct _oe_fs_device_ops
{
    oe_device_ops_t base;

    int (*clone)(oe_device_t* device, oe_device_t** new_device);

    int (*mount)(
        oe_device_t* fs,
        const char* source,
        const char* target,
        unsigned long flags);

    int (*unmount)(oe_device_t* fs, const char* target);

    oe_fd_t* (*open)(
        oe_device_t* fs,
        const char* pathname,
        int flags,
        oe_mode_t mode);

    int (*stat)(oe_device_t* fs, const char* pathname, struct oe_stat* buf);

    int (*access)(oe_device_t* fs, const char* pathname, int mode);

    int (*link)(oe_device_t* fs, const char* oldpath, const char* newpath);

    int (*unlink)(oe_device_t* fs, const char* pathname);

    int (*rename)(oe_device_t* fs, const char* oldpath, const char* newpath);

    int (*truncate)(oe_device_t* fs, const char* path, oe_off_t length);

    int (*mkdir)(oe_device_t* fs, const char* pathname, oe_mode_t mode);

    int (*rmdir)(oe_device_t* fs, const char* pathname);
};

OE_EXTERNC_END

#endif // _OE_POSIX_FSOPS_H
