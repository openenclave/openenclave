// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/dirent.h>
#include <openenclave/corelibc/fcntl.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/posix/device.h>
#include <openenclave/internal/posix/fdtable.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/internal/trace.h>

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
        OE_RAISE_ERRNO(OE_EINVAL);

    if ((fd = oe_open_d(devid, pathname, OE_O_RDONLY | OE_O_DIRECTORY, 0)) < 0)
        OE_RAISE_ERRNO_F(oe_errno, "pathname=%s", pathname);

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
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_getdents((unsigned int)dir->fd, &dir->buf, count) != (int)count)
    {
        if (oe_errno)
            OE_RAISE_ERRNO(oe_errno);

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
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = oe_close(dir->fd);

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
        OE_RAISE_ERRNO(OE_EBADF);

    if (file->ops.fs->getdents == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = (*file->ops.fs->getdents)(file, dirp, count);

done:
    return ret;
}
