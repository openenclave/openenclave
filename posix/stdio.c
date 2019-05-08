// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdio.h>
#include <openenclave/internal/device/device.h>
#include <openenclave/internal/device/raise.h>
#include <openenclave/internal/trace.h>
#include "mount.h"

int oe_rename(const char* oldpath, const char* newpath)
{
    int ret = -1;
    oe_device_t* fs = NULL;
    oe_device_t* newfs = NULL;
    char filepath[OE_PATH_MAX];
    char newfilepath[OE_PATH_MAX];

    if (!(fs = oe_mount_resolve(oldpath, filepath)))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(newfs = oe_mount_resolve(newpath, newfilepath)))
        OE_RAISE_ERRNO(oe_errno);

    if (fs != newfs)
        OE_RAISE_ERRNO(OE_EXDEV);

    if (fs->ops.fs->rename == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

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
            OE_RAISE_ERRNO(OE_EINVAL);

        if ((ret = dev->ops.fs->rename(dev, oldpath, newpath)) == -1)
        {
            OE_RAISE_ERRNO_F(
                oe_errno,
                "ret=%d oldpath=%s newpath=%s",
                ret,
                oldpath,
                newpath);
        }
    }

done:
    return ret;
}
