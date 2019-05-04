// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdio.h>
#include <openenclave/internal/trace.h>
#include "device.h"
#include "mount.h"

int oe_rename(const char* oldpath, const char* newpath)
{
    int ret = -1;
    oe_device_t* fs = NULL;
    oe_device_t* newfs = NULL;
    char filepath[OE_PATH_MAX];
    char newfilepath[OE_PATH_MAX];

    if (!(fs = oe_mount_resolve(oldpath, filepath)))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (!(newfs = oe_mount_resolve(newpath, newfilepath)))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (fs != newfs)
    {
        oe_errno = OE_EXDEV;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (fs->ops.fs->rename == NULL)
    {
        oe_errno = OE_EPERM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    ret = (*fs->ops.fs->rename)(fs, filepath, newfilepath);

done:
    return ret;
}

int oe_rename_d(uint64_t devid, const char* oldpath, const char* newpath)
{
    int ret = -1;

    if (devid == OE_DEVID_NONE)
    {
        ret = oe_rename(oldpath, newpath);
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

        if ((ret = dev->ops.fs->rename(dev, oldpath, newpath)) != 0)
        {
            OE_TRACE_ERROR(
                "devid=%lu oldpath=%s newpath=%s ret=%d",
                devid,
                oldpath,
                newpath,
                ret);
        }
    }

done:
    return ret;
}
