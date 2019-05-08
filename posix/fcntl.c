// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/internal/device/device.h>
#include <openenclave/internal/device/fdtable.h>
#include <openenclave/internal/device/raise.h>
#include <openenclave/internal/trace.h>
#include "mount.h"
#include "posix_t.h"

int __oe_fcntl(int fd, int cmd, uint64_t arg)
{
    int ret = -1;
    oe_device_t* device;

    if (!(device = oe_fdtable_get(fd, OE_DEVICE_TYPE_NONE)))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (device->ops.base->fcntl == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = (*device->ops.base->fcntl)(device, cmd, arg);

done:
    return ret;
}

int oe_open(const char* pathname, int flags, oe_mode_t mode)
{
    int ret = -1;
    int fd;
    oe_device_t* fs;
    oe_device_t* file;
    char filepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(pathname, filepath)))
        OE_RAISE_ERRNO(oe_errno);

    if (!(file = (*fs->ops.fs->open)(fs, filepath, flags, mode)))
        OE_RAISE_ERRNO_F(oe_errno, "pathname=%s", pathname);

    if ((fd = oe_fdtable_assign(file)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    ret = fd;

done:
    return ret;
}

int oe_open_d(uint64_t devid, const char* pathname, int flags, oe_mode_t mode)
{
    int ret = -1;

    if (devid == OE_DEVID_NONE)
    {
        ret = oe_open(pathname, flags, mode);
    }
    else
    {
        oe_device_t* dev = oe_get_device(devid, OE_DEVICE_TYPE_FILESYSTEM);
        oe_device_t* file;

        if (!dev)
            OE_RAISE_ERRNO(OE_EINVAL);

        if (!(file = (*dev->ops.fs->open)(dev, pathname, flags, mode)))
            OE_RAISE_ERRNO_F(oe_errno, "pathname=%s mode=%u", pathname, mode);

        if ((ret = oe_fdtable_assign(file)) == -1)
            OE_RAISE_ERRNO(oe_errno);
    }

done:
    return ret;
}
