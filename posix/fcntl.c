// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/internal/device/device.h>
#include <openenclave/internal/device/fdtable.h>
#include <openenclave/internal/trace.h>
#include "mount.h"
#include "posix_t.h"

int __oe_fcntl(int fd, int cmd, uint64_t arg)
{
    int ret = -1;
    oe_device_t* device;

    if (!(device = oe_fdtable_get(fd, OE_DEVICE_TYPE_NONE)))
    {
        OE_TRACE_ERROR("no device found fd=%d", fd);
        goto done;
    }

    if (device->ops.base->fcntl == NULL)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

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
    {
        OE_TRACE_ERROR("pathname = %s : filepath = %s", pathname, filepath);
        goto done;
    }

    if (!(file = (*fs->ops.fs->open)(fs, filepath, flags, mode)))
    {
        OE_TRACE_ERROR(
            "pathname = %s filepath = %s flags=%d mode =%d",
            pathname,
            filepath,
            flags,
            mode);
        goto done;
    }

    if ((fd = oe_fdtable_assign(file)) == -1)
    {
        (*fs->ops.fs->base.close)(file);
        OE_TRACE_ERROR("oe_fdtable_assign for pathname=%s", pathname);
        goto done;
    }

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
        {
            oe_errno = OE_EINVAL;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        if (!(file = (*dev->ops.fs->open)(dev, pathname, flags, mode)))
        {
            OE_TRACE_ERROR(
                "devid=%lu pathname=%s flags=%d mode=%d",
                devid,
                pathname,
                flags,
                mode);
            goto done;
        }

        if ((ret = oe_fdtable_assign(file)) == -1)
        {
            OE_TRACE_ERROR("oe_fdtable_assign devid=%lu", devid);
            (*dev->ops.fs->base.close)(file);
            goto done;
        }
    }

done:
    return ret;
}
