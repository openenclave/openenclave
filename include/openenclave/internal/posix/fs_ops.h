// Copyright (c) Microsoft Corporation. All rights reserved._ops
// Licensed under the MIT License.

#ifndef _OE_FS_OPS_H
#define _OE_FS_OPS_H

#include <openenclave/bits/types.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/sys/mount.h>
#include <openenclave/corelibc/sys/stat.h>
#include <openenclave/internal/posix/device_ops.h>
#include <openenclave/internal/posix/fs.h>

OE_EXTERNC_BEGIN

typedef struct _oe_file oe_file_t;
typedef struct _oe_fs_ops oe_fs_ops_t;
typedef struct _oe_device oe_device_t;

struct _oe_fs_ops
{
    oe_device_ops_t base;

    int (*mount)(
        oe_device_t* fs,
        const char* source,
        const char* target,
        unsigned long flags);

    int (*unmount)(oe_device_t* fs, const char* target);

    oe_device_t* (
        *open)(oe_device_t* fs, const char* pathname, int flags, mode_t mode);

    off_t (*lseek)(oe_device_t* file, off_t offset, int whence);

    int (*getdents)(
        oe_device_t* file,
        struct oe_dirent* dirp,
        unsigned int count);

    int (*stat)(oe_device_t* fs, const char* pathname, struct oe_stat* buf);

    int (*access)(oe_device_t* fs, const char* pathname, int mode);

    int (*link)(oe_device_t* fs, const char* oldpath, const char* newpath);

    int (*unlink)(oe_device_t* fs, const char* pathname);

    int (*rename)(oe_device_t* fs, const char* oldpath, const char* newpath);

    int (*truncate)(oe_device_t* fs, const char* path, off_t length);

    int (*mkdir)(oe_device_t* fs, const char* pathname, mode_t mode);

    int (*rmdir)(oe_device_t* fs, const char* pathname);
};

OE_EXTERNC_END

#endif // _OE_FS_OPS_H
