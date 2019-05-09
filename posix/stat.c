// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/sys/stat.h>
#include <openenclave/internal/posix/device.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/internal/trace.h>
#include "mount.h"

int oe_stat(const char* pathname, struct oe_stat* buf)
{
    int ret = -1;
    oe_device_t* fs = NULL;
    char filepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(pathname, filepath)))
        OE_RAISE_ERRNO(oe_errno);

    ret = OE_CALL_FS(stat, fs, filepath, buf);

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
            OE_RAISE_ERRNO(OE_EINVAL);

        ret = OE_CALL_FS(stat, dev, pathname, buf);
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
        OE_RAISE_ERRNO(oe_errno);

    ret = OE_CALL_FS(mkdir, fs, filepath, mode);

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
            OE_RAISE_ERRNO(OE_EINVAL);

        ret = OE_CALL_FS(mkdir, dev, pathname, mode);
    }

done:
    return ret;
}
