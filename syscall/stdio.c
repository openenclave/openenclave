// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/syscall/device.h>
#include <openenclave/internal/syscall/raise.h>
#include <openenclave/internal/trace.h>
#include "mount.h"

int oe_rename(const char* oldpath, const char* newpath)
{
    int ret = -1;
    oe_device_t* fs = NULL;
    oe_device_t* newfs = NULL;
    typedef struct _variables
    {
        char filepath[OE_PATH_MAX];
        char newfilepath[OE_PATH_MAX];
    } variables_t;
    variables_t* v = NULL;

    if (!(v = oe_malloc(sizeof(variables_t))))
        OE_RAISE_ERRNO(OE_ENOMEM);

    if (!(fs = oe_mount_resolve(oldpath, v->filepath)))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(newfs = oe_mount_resolve(newpath, v->newfilepath)))
        OE_RAISE_ERRNO(oe_errno);

    if (fs != newfs)
        OE_RAISE_ERRNO(OE_EXDEV);

    ret = fs->ops.fs.rename(fs, v->filepath, v->newfilepath);

done:

    if (v)
        oe_free(v);

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

        if (!(dev = oe_device_table_get(devid, OE_DEVICE_TYPE_FILE_SYSTEM)))
            OE_RAISE_ERRNO(OE_EINVAL);

        if ((ret = dev->ops.fs.rename(dev, oldpath, newpath)) == -1)
        {
            OE_RAISE_ERRNO_MSG(
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
