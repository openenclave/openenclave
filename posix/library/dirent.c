// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/dirent.h>
#include <openenclave/corelibc/fcntl.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/trace.h>
#include "include/device.h"
#include "include/fdtable.h"

#define DIR_MAGIC 0x09180827

struct _OE_DIR
{
    uint32_t magic;
    int fd;
    struct oe_dirent buf;
};

OE_DIR* oe_opendir_d(uint64_t devid, const char* pathname)
{
    OE_DIR* ret = NULL;
    OE_DIR* dir = oe_calloc(1, sizeof(OE_DIR));
    int fd = -1;

    if (!dir)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if ((fd = oe_open_d(devid, pathname, OE_O_RDONLY | OE_O_DIRECTORY, 0)) < 0)
    {
        OE_TRACE_ERROR("devid=%lu pathname=%s", devid, pathname);
        goto done;
    }

    dir->magic = DIR_MAGIC;
    dir->fd = fd;

    ret = dir;
    dir = NULL;
    fd = -1;

done:

    if (dir)
        oe_free(dir);

    if (fd >= 0)
        oe_close(fd);

    return ret;
}

OE_DIR* oe_opendir(const char* pathname)
{
    return oe_opendir_d(OE_DEVID_NONE, pathname);
}

struct oe_dirent* oe_readdir(OE_DIR* dir)
{
    struct oe_dirent* ret = NULL;
    unsigned int count = (unsigned int)sizeof(struct oe_dirent);

    if (!dir || dir->magic != DIR_MAGIC)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (oe_getdents((unsigned int)dir->fd, &dir->buf, count) != (int)count)
    {
        if (oe_errno)
            OE_TRACE_ERROR("count=%d", count);
        goto done;
    }

    ret = &dir->buf;

done:
    return ret;
}

int oe_closedir(OE_DIR* dir)
{
    int ret = -1;

    if (!dir || dir->magic != DIR_MAGIC)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if ((ret = oe_close(dir->fd)) == 0)
    {
        dir->magic = 0;
    }
    oe_free(dir);
done:
    return ret;
}

void oe_rewinddir(OE_DIR* dir)
{
    if (dir && dir->magic == DIR_MAGIC)
    {
        oe_lseek(dir->fd, 0, OE_SEEK_SET);
    }
}

int oe_getdents(unsigned int fd, struct oe_dirent* dirp, unsigned int count)
{
    int ret = -1;
    oe_device_t* file;

    if (!(file = oe_fdtable_get((int)fd, OE_DEVICE_TYPE_FILE)))
    {
        oe_errno = OE_EBADF;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (file->ops.fs->getdents == NULL)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    ret = (*file->ops.fs->getdents)(file, dirp, count);

done:
    return ret;
}
