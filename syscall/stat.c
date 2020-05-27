// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/syscall/device.h>
#include <openenclave/internal/syscall/fdtable.h>
#include <openenclave/internal/syscall/raise.h>
#include <openenclave/internal/syscall/sys/stat.h>
#include <openenclave/internal/trace.h>
#include "mount.h"

int oe_stat(const char* pathname, struct oe_stat_t* buf)
{
    int ret = -1;
    oe_device_t* fs = NULL;
    char filepath[OE_PATH_MAX];

    if (!(fs = oe_mount_resolve(pathname, filepath)))
        OE_RAISE_ERRNO(oe_errno);

    ret = fs->ops.fs.stat(fs, filepath, buf);

done:
    return ret;
}

int oe_stat_d(uint64_t devid, const char* pathname, struct oe_stat_t* buf)
{
    int ret = -1;

    if (devid == OE_DEVID_NONE)
    {
        ret = oe_stat(pathname, buf);
    }
    else
    {
        oe_device_t* dev;

        if (!(dev = oe_device_table_get(devid, OE_DEVICE_TYPE_FILE_SYSTEM)))
            OE_RAISE_ERRNO(OE_EINVAL);

        ret = dev->ops.fs.stat(dev, pathname, buf);
    }

done:
    return ret;
}

int oe_fstat(int fd, struct oe_stat_t* buf)
{
    int ret = -1;
    oe_fd_t* const file = oe_fdtable_get(fd, OE_FD_TYPE_FILE);
    if (!file)
        OE_RAISE_ERRNO(oe_errno);
    ret = file->ops.file.fstat(file, buf);
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

    ret = fs->ops.fs.mkdir(fs, filepath, mode);

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

        if (!(dev = oe_device_table_get(devid, OE_DEVICE_TYPE_FILE_SYSTEM)))
            OE_RAISE_ERRNO(OE_EINVAL);

        ret = dev->ops.fs.mkdir(dev, pathname, mode);
    }

done:
    return ret;
}
