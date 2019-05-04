// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/sys/stat.h>
#include <openenclave/internal/trace.h>
#include "device.h"
#include "mount.h"

int oe_stat(const char* pathname, struct oe_stat* buf)
{
    int ret = -1;
    oe_device_t* fs = NULL;
    char filepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(pathname, filepath)))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (fs->ops.fs->stat == NULL)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    ret = (*fs->ops.fs->stat)(fs, filepath, buf);

done:
    return ret;
}

int oe_stat_d(uint64_t devid, const char* pathname, struct oe_stat* buf)
{
    int ret = -1;

    if (devid == OE_DEVID_NONE)
    {
        ret = oe_stat(pathname, buf);
    }
    else
    {
        oe_device_t* dev;

        if (!(dev = oe_get_device(devid, OE_DEVICE_TYPE_FILESYSTEM)))
        {
            oe_errno = OE_EINVAL;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        if ((ret = dev->ops.fs->stat(dev, pathname, buf)) != 0)
        {
            OE_TRACE_ERROR(
                "devid=%lu pathname=%s ret=%d", devid, pathname, ret);
        }
    }

done:
    return ret;
}

int oe_mkdir(const char* pathname, oe_mode_t mode)
{
    int ret = -1;
    oe_device_t* fs = NULL;
    char filepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(pathname, filepath)))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (fs->ops.fs->mkdir == NULL)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    ret = (*fs->ops.fs->mkdir)(fs, filepath, mode);

done:
    return ret;
}

int oe_mkdir_d(uint64_t devid, const char* pathname, oe_mode_t mode)
{
    int ret = -1;

    if (devid == OE_DEVID_NONE)
    {
        ret = oe_mkdir(pathname, mode);
    }
    else
    {
        oe_device_t* dev;

        if (!(dev = oe_get_device(devid, OE_DEVICE_TYPE_FILESYSTEM)))
        {
            oe_errno = OE_EINVAL;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        if ((ret = dev->ops.fs->mkdir(dev, pathname, mode)) != 0)
        {
            OE_TRACE_ERROR(
                "devid=%lu pathname=%s mode=%d ret=%d",
                devid,
                pathname,
                (int)mode,
                ret);
        }
    }

done:
    return ret;
}
