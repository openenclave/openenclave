// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE

// clang-format off
#include <openenclave/enclave.h>
// clang-format on

#include "device.h"
#include <openenclave/corelibc/limits.h>
#include "fs_ops.h"
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/print.h>
#include "posix_t.h"
#include <openenclave/corelibc/dirent.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/fcntl.h>
#include <openenclave/bits/module.h>
#include <openenclave/internal/trace.h>

/*
**==============================================================================
**
** hostfs operations:
**
**==============================================================================
*/

#define DEVICE_NAME "hostfs"
#define FS_MAGIC 0x5f35f964
#define FILE_MAGIC 0xfe48c6ff
#define DIR_MAGIC 0x8add1b0b

typedef struct _fs
{
    struct _oe_device base;
    uint32_t magic;
    unsigned long mount_flags;
    char mount_source[OE_PATH_MAX];
} fs_t;

typedef struct _file
{
    struct _oe_device base;
    uint32_t magic;
    int host_fd;
    uint32_t ready_mask;
    oe_device_t* dir;
} file_t;

typedef struct _dir
{
    struct _oe_device base;
    uint32_t magic;
    uint64_t host_dir;
    struct oe_dirent entry;
} dir_t;

static int _get_open_access_mode(int flags)
{
    return (flags & 000000003);
}

static fs_t* _cast_fs(const oe_device_t* device)
{
    fs_t* fs = (fs_t*)device;

    if (fs == NULL || fs->magic != FS_MAGIC)
    {
        OE_TRACE_ERROR("invalid parameter");
        return NULL;
    }

    return fs;
}

static file_t* _cast_file(const oe_device_t* device)
{
    file_t* file = (file_t*)device;

    if (file == NULL || file->magic != FILE_MAGIC)
    {
        OE_TRACE_ERROR("invalid parameter");
        return NULL;
    }

    return file;
}

static dir_t* _cast_dir(const oe_device_t* device)
{
    dir_t* dir = (dir_t*)device;

    if (dir == NULL || dir->magic != DIR_MAGIC)
    {
        OE_TRACE_ERROR("invalid parameter");
        return NULL;
    }

    return dir;
}

OE_INLINE bool _is_rdonly(const fs_t* fs)
{
    return (fs->mount_flags & OE_MS_RDONLY);
}

OE_INLINE bool _is_root(const char* path)
{
    return path[0] == '/' && path[1] == '\0';
}

/* Expand path to include the mount_source (needed by host side) */
static int _expand_path(
    const fs_t* fs,
    const char* suffix,
    char path[OE_PATH_MAX])
{
    const size_t n = OE_PATH_MAX;
    int ret = -1;

    if (_is_root(fs->mount_source))
    {
        if (oe_strlcpy(path, suffix, OE_PATH_MAX) >= n)
        {
            oe_errno = ENAMETOOLONG;
            OE_TRACE_ERROR("oe_errno = %d", oe_errno);
            goto done;
        }
    }
    else
    {
        if (oe_strlcpy(path, fs->mount_source, OE_PATH_MAX) >= n)
        {
            oe_errno = ENAMETOOLONG;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        if (!_is_root(suffix))
        {
            if (oe_strlcat(path, "/", OE_PATH_MAX) >= n)
            {
                oe_errno = ENAMETOOLONG;
                OE_TRACE_ERROR("oe_errno=%d", oe_errno);
                goto done;
            }

            if (oe_strlcat(path, suffix, OE_PATH_MAX) >= n)
            {
                oe_errno = ENAMETOOLONG;
                OE_TRACE_ERROR("oe_errno=%d", oe_errno);
                goto done;
            }
        }
    }

    ret = 0;

done:
    return ret;
}

static int _hostfs_mount(
    oe_device_t* dev,
    const char* source,
    const char* target,
    unsigned long flags)
{
    int ret = -1;
    fs_t* fs = _cast_fs(dev);

    if (!fs || !source || !target)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    fs->mount_flags = flags;
    oe_strlcpy(fs->mount_source, source, sizeof(fs->mount_source));

    ret = 0;

done:
    return ret;
}

static int _hostfs_unmount(oe_device_t* dev, const char* target)
{
    int ret = -1;
    fs_t* fs = _cast_fs(dev);

    if (!fs || !target)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    ret = 0;

done:
    return ret;
}

static ssize_t _hostfs_read(oe_device_t*, void* buf, size_t count);

static int _hostfs_close(oe_device_t*);

static int _hostfs_clone(oe_device_t* device, oe_device_t** new_device)
{
    int ret = -1;
    fs_t* fs = _cast_fs(device);
    fs_t* new_fs = NULL;

    if (!fs || !new_device)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (!(new_fs = oe_calloc(1, sizeof(fs_t))))
    {
        oe_errno = ENOMEM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    memcpy(new_fs, fs, sizeof(fs_t));

    *new_device = &new_fs->base;
    ret = 0;

done:
    return ret;
}

static int _hostfs_release(oe_device_t* device)
{
    int ret = -1;
    fs_t* fs = _cast_fs(device);

    if (!fs)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    oe_free(fs);
    ret = 0;
done:
    return ret;
}

static int _hostfs_shutdown(oe_device_t* device)
{
    int ret = -1;
    fs_t* fs = _cast_fs(device);

    if (!fs)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    ret = 0;

done:
    return ret;
}

static oe_device_t* _hostfs_open_file(
    oe_device_t* fs_,
    const char* pathname,
    int flags,
    oe_mode_t mode)
{
    oe_device_t* ret = NULL;
    fs_t* fs = _cast_fs(fs_);
    file_t* file = NULL;
    char full_pathname[OE_PATH_MAX];
    int retval = -1;

    oe_errno = 0;

    /* Check parameters */
    if (!fs || !pathname)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs) && _get_open_access_mode(flags) != OE_O_RDONLY)
    {
        oe_errno = EPERM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Call */
    {
        int err;

        if (_expand_path(fs, pathname, full_pathname) != 0)
        {
            OE_TRACE_ERROR(
                "pathname=%s full_pathname=%s", pathname, full_pathname);
            goto done;
        }

        if (oe_posix_open_ocall(&retval, full_pathname, flags, mode, &err) !=
            OE_OK)
        {
            oe_errno = EINVAL;
            OE_TRACE_ERROR(
                "full_pathname=%s flags=%d oe_errno=%d",
                full_pathname,
                flags,
                oe_errno);
            goto done;
        }

        if (retval < 0)
        {
            oe_errno = err;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }
    }

    /* Output */
    {
        if (!(file = oe_calloc(1, sizeof(file_t))))
        {
            oe_errno = ENOMEM;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        file->base.type = OE_DEVICE_TYPE_FILE;
        file->base.name = DEVICE_NAME;
        file->magic = FILE_MAGIC;
        file->base.ops.fs = fs->base.ops.fs;
        file->host_fd = retval;
    }

    ret = &file->base;
    file = NULL;

done:

    if (file)
        oe_free(file);

    return ret;
}

static oe_device_t* _hostfs_opendir(oe_device_t* fs, const char* name);
static int _hostfs_closedir(oe_device_t* file);

static oe_device_t* _hostfs_open_directory(
    oe_device_t* fs_,
    const char* pathname,
    int flags,
    oe_mode_t mode)
{
    oe_device_t* ret = NULL;
    fs_t* fs = _cast_fs(fs_);
    file_t* file = NULL;
    oe_device_t* dir = NULL;

    oe_errno = 0;

    OE_UNUSED(mode);

    /* Check parameters */
    if (!fs || !pathname || !(flags & OE_O_DIRECTORY))
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Directories can only be opened for read access. */
    if (_get_open_access_mode(flags) != OE_O_RDONLY)
    {
        oe_errno = EACCES;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Attempt to open the directory. */
    if (!(dir = _hostfs_opendir(fs_, pathname)))
    {
        OE_TRACE_ERROR("pathname = %s", pathname);
        goto done;
    }

    /* Allocate and initialize the file struct. */
    {
        if (!(file = oe_calloc(1, sizeof(file_t))))
        {
            oe_errno = ENOMEM;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        file->base.type = OE_DEVICE_TYPE_FILE;
        file->base.name = DEVICE_NAME;
        file->magic = FILE_MAGIC;
        file->base.ops.fs = fs->base.ops.fs;
        file->host_fd = -1;
        file->dir = dir;
    }

    ret = &file->base;
    file = NULL;
    dir = NULL;

done:

    if (file)
        oe_free(file);

    if (dir)
        _hostfs_closedir(dir);

    return ret;
}

static oe_device_t* _hostfs_open(
    oe_device_t* fs,
    const char* pathname,
    int flags,
    oe_mode_t mode)
{
    if ((flags & OE_O_DIRECTORY))
    {
        return _hostfs_open_directory(fs, pathname, flags, mode);
    }
    else
    {
        return _hostfs_open_file(fs, pathname, flags, mode);
    }
}

static int _hostfs_dup(oe_device_t* file_, oe_device_t** new_file)
{
    int ret = -1;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    /* Check parameters. */
    if (!file)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Call */
    {
        int err = 0;
        int retval = -1;

        if (oe_posix_dup_ocall(&retval, file->host_fd, &err) != OE_OK)
        {
            oe_errno = EINVAL;
            OE_TRACE_ERROR("oe_errno = %d", oe_errno);
            goto done;
        }

        if (retval != -1)
        {
            file_t* f = NULL;
            _hostfs_clone(file_, (oe_device_t**)&f);

            if (!f)
            {
                oe_errno = EINVAL;
                OE_TRACE_ERROR("oe_errno=%d", oe_errno);
                goto done;
            }

            f->host_fd = retval;
            *new_file = (oe_device_t*)f;
        }
        else
        {
            oe_errno = err;
            OE_TRACE_ERROR("oe_errno = %d", oe_errno);
            goto done;
        }
    }

    ret = 0;

done:
    return ret;
}

static ssize_t _hostfs_read(oe_device_t* file_, void* buf, size_t count)
{
    ssize_t ret = -1;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    if (!file)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Call the host. */
    if (oe_posix_read_ocall(&ret, file->host_fd, buf, count, &oe_errno) !=
        OE_OK)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("host_fd=%d oe_errno = %d", file->host_fd, oe_errno);
        goto done;
    }

done:
    return ret;
}

static struct oe_dirent* _hostfs_readdir(oe_device_t* dir_);

static int _hostfs_getdents(
    oe_device_t* file_,
    struct oe_dirent* dirp,
    unsigned int count)
{
    int ret = -1;
    int bytes = 0;
    file_t* file = _cast_file(file_);
    unsigned int i;
    unsigned int n = count / sizeof(struct oe_dirent);

    oe_errno = 0;

    if (!file || !file->dir || !dirp)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Read the entries one-by-one. */
    for (i = 0; i < n; i++)
    {
        oe_errno = 0;

        struct oe_dirent* ent;

        if (!(ent = _hostfs_readdir(file->dir)))
        {
            if (oe_errno)
            {
                OE_TRACE_ERROR("_hostfs_readdir failed");
                goto done;
            }

            break;
        }

        memcpy(dirp, ent, sizeof(struct oe_dirent));
        bytes += (int)sizeof(struct oe_dirent);
        dirp++;
    }

    ret = bytes;

done:
    return ret;
}

static ssize_t _hostfs_write(oe_device_t* file, const void* buf, size_t count)
{
    ssize_t ret = -1;
    file_t* f = _cast_file(file);

    oe_errno = 0;

    /* Check parameters. */
    if (!f || (count && !buf))
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Call the host. */
    if (oe_posix_write_ocall(&ret, f->host_fd, buf, count, &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno = %d", oe_errno);
        goto done;
    }

done:
    return ret;
}

static oe_off_t _hostfs_lseek_file(
    oe_device_t* file,
    oe_off_t offset,
    int whence)
{
    oe_off_t ret = -1;
    file_t* f = _cast_file(file);

    oe_errno = 0;

    if (!file)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (oe_posix_lseek_ocall(&ret, f->host_fd, offset, whence, &oe_errno) !=
        OE_OK)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno = %d", oe_errno);
        goto done;
    }

done:
    return ret;
}

static int _hostfs_rewinddir(oe_device_t* dir_)
{
    int ret = -1;
    dir_t* dir = _cast_dir(dir_);

    if (!dir)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    oe_posix_rewinddir_ocall(dir->host_dir);

    ret = 0;

done:
    return ret;
}

static oe_off_t _hostfs_lseek_dir(
    oe_device_t* file_,
    oe_off_t offset,
    int whence)
{
    oe_off_t ret = -1;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    if (!file || !file->dir || offset != 0 || whence != OE_SEEK_SET)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (_hostfs_rewinddir(file->dir) != 0)
    {
        OE_TRACE_ERROR("_hostfs_rewinddir failed");
        goto done;
    }

    ret = 0;

done:
    return ret;
}

static oe_off_t _hostfs_lseek(oe_device_t* file_, oe_off_t offset, int whence)
{
    oe_off_t ret = -1;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    if (!file)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (file->dir)
    {
        ret = _hostfs_lseek_dir(file_, offset, whence);
    }
    else
    {
        ret = _hostfs_lseek_file(file_, offset, whence);
    }

done:
    if (ret == -1)
    {
        OE_TRACE_ERROR("_hostfs_lseek failed");
    }
    return ret;
}

static int _hostfs_close_file(oe_device_t* file)
{
    int ret = -1;
    file_t* f = _cast_file(file);

    oe_errno = 0;

    if (!f)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (oe_posix_close_ocall(&ret, f->host_fd, &oe_errno) != OE_OK)
    {
        OE_TRACE_ERROR("oe_posix_close_ocall failed");
        oe_errno = EINVAL;
        goto done;
    }

    if (ret == 0)
        oe_free(file);

    ret = 0;

done:
    return ret;
}

static int _hostfs_close_directory(oe_device_t* file_)
{
    int ret = -1;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    /* Check parameters. */
    if (!file || !file->dir)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Release the directory object. */
    if (_hostfs_closedir(file->dir) != 0)
    {
        OE_TRACE_ERROR("_hostfs_closedir failed");
        goto done;
    }

    /* Release the file object. */
    oe_free(file);

    ret = 0;

done:
    return ret;
}

static int _hostfs_close(oe_device_t* file_)
{
    int ret = -1;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    /* Check parameters. */
    if (!file)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (file->dir)
    {
        ret = _hostfs_close_directory(file_);
    }
    else
    {
        ret = _hostfs_close_file(file_);
    }

done:
    return ret;
}

static int _hostfs_ioctl(
    oe_device_t* file_,
    unsigned long request,
    uint64_t arg)
{
    int ret = -1;
    file_t* file = _cast_file(file_);
    OE_UNUSED(file);
    OE_UNUSED(request);
    OE_UNUSED(arg);

    if (!file)
    {
        oe_errno = EINVAL;
        goto done;
    }

    oe_errno = ENOTSUP;
    OE_TRACE_ERROR(
        "oe_errno=%d fd=%d request=%lx", file->host_fd, oe_errno, request);

done:
    return ret;
}

static int _hostfs_fcntl(oe_device_t* file_, int cmd, uint64_t arg)
{
    int ret = -1;
    file_t* file = _cast_file(file_);
    int err = 0;

    oe_errno = 0;

    if (!file)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Call the host. */
    if (oe_posix_fcntl_ocall(&ret, file->host_fd, cmd, arg, &err) != OE_OK)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR(
            "host_fd=%d cmd=%d arg=%lu oe_errno=%d",
            file->host_fd,
            cmd,
            arg,
            oe_errno);
        goto done;
    }

    if (ret == -1)
    {
        oe_errno = err;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
    }

done:
    return ret;
}

static oe_device_t* _hostfs_opendir(oe_device_t* fs_, const char* name)
{
    oe_device_t* ret = NULL;
    fs_t* fs = _cast_fs(fs_);
    dir_t* dir = NULL;
    char full_name[OE_PATH_MAX];
    uint64_t retval = 0;

    if (!fs || !name)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (_expand_path(fs, name, full_name) != 0)
    {
        OE_TRACE_ERROR("name=%s full_name=%s", name, full_name);
        goto done;
    }

    if (oe_posix_opendir_ocall(&retval, full_name, &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("full_name=%s oe_errno =%d", full_name, oe_errno);
        goto done;
    }

    {
        if (!(dir = oe_calloc(1, sizeof(dir_t))))
        {
            oe_errno = ENOMEM;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        dir->base.type = OE_DEVICE_TYPE_DIRECTORY;
        dir->base.name = DEVICE_NAME;
        dir->magic = DIR_MAGIC;
        dir->base.ops.fs = fs->base.ops.fs;
        dir->host_dir = retval;
    }

    ret = &dir->base;
    dir = NULL;

done:

    if (dir)
        oe_free(dir);

    return ret;
}

static struct oe_dirent* _hostfs_readdir(oe_device_t* dir_)
{
    struct oe_dirent* ret = NULL;
    dir_t* dir = _cast_dir(dir_);
    int retval = -1;
    int err = 0;

    oe_errno = 0;

    if (!dir)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Call the host. */
    {
        oe_result_t result;

        if ((result = oe_posix_readdir_ocall(
                 &retval,
                 dir->host_dir,
                 &dir->entry.d_ino,
                 &dir->entry.d_off,
                 &dir->entry.d_reclen,
                 &dir->entry.d_type,
                 dir->entry.d_name,
                 sizeof(dir->entry.d_name),
                 &err)) != OE_OK)
        {
            oe_errno = err;
            OE_TRACE_ERROR("%s", oe_result_str(result));
            goto done;
        }

        /* Fix up the record length. */
        if (retval == 0)
            dir->entry.d_reclen = sizeof(struct oe_dirent);

        oe_errno = err;
    }

    /* Handle any error. */
    if (retval == -1)
    {
        memset(&dir->entry, 0, sizeof(dir->entry));

        if (oe_errno)
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);

        goto done;
    }

    ret = &dir->entry;

done:

    return ret;
}

static int _hostfs_closedir(oe_device_t* dir)
{
    int ret = -1;
    dir_t* d = _cast_dir(dir);
    int retval = -1;
    int err = 0;

    oe_errno = 0;

    if (!d)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (oe_posix_closedir_ocall(&retval, d->host_dir, &err) != OE_OK)
    {
        oe_errno = err;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    oe_errno = err;

    if (retval == 0)
        ret = 0;

    oe_free(dir);

done:

    return ret;
}

static int _hostfs_stat(
    oe_device_t* fs_,
    const char* pathname,
    struct oe_stat* buf)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    char full_pathname[OE_PATH_MAX];

    if (buf)
        memset(buf, 0, sizeof(*buf));

    if (!fs || !pathname || !buf)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (_expand_path(fs, pathname, full_pathname) != 0)
    {
        OE_TRACE_ERROR("pathname=%s full_pathname=%s", pathname, full_pathname);
        goto done;
    }

    if (oe_posix_stat_ocall(&ret, full_pathname, buf, &oe_errno) != OE_OK)
    {
        OE_TRACE_ERROR(
            "full_pathname=%s oe_errno =%d", full_pathname, oe_errno);
        goto done;
    }

done:

    return ret;
}

static int _hostfs_access(oe_device_t* fs_, const char* pathname, int mode)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    char full_pathname[OE_PATH_MAX];
    const uint32_t MASK = (OE_R_OK | OE_W_OK | OE_X_OK);

    /* Check parameters */
    if (!fs || !pathname || ((uint32_t)mode & ~MASK))
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (_expand_path(fs, pathname, full_pathname) != 0)
    {
        OE_TRACE_ERROR("pathname=%s full_pathname=%s", pathname, full_pathname);
        goto done;
    }

    if (oe_posix_access_ocall(&ret, full_pathname, mode, &oe_errno) != OE_OK)
    {
        OE_TRACE_ERROR(
            "full_pathname=%s mode=%d oe_errno =%d",
            full_pathname,
            mode,
            oe_errno);
        goto done;
    }

done:

    return ret;
}

static int _hostfs_link(
    oe_device_t* fs_,
    const char* oldpath,
    const char* newpath)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    char full_oldpath[OE_PATH_MAX];
    char full_newpath[OE_PATH_MAX];

    if (!fs || !oldpath || !newpath)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = EPERM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (_expand_path(fs, oldpath, full_oldpath) != 0)
    {
        OE_TRACE_ERROR("oldpath=%s full_oldpath=%s", oldpath, full_oldpath);
        goto done;
    }

    if (_expand_path(fs, newpath, full_newpath) != 0)
    {
        OE_TRACE_ERROR("newpath=%s full_newpath=%s", newpath, full_newpath);
        goto done;
    }

    if (oe_posix_link_ocall(&ret, full_oldpath, full_newpath, &oe_errno) !=
        OE_OK)
    {
        OE_TRACE_ERROR(
            "full_oldpath=%s full_newpath=%s oe_errno =%d",
            full_oldpath,
            full_newpath,
            oe_errno);
        goto done;
    }

done:

    return ret;
}

static int _hostfs_unlink(oe_device_t* fs_, const char* pathname)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    char full_pathname[OE_PATH_MAX];

    if (!fs)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = EPERM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (_expand_path(fs, pathname, full_pathname) != 0)
    {
        OE_TRACE_ERROR("pathname=%s full_pathname=%s", pathname, full_pathname);
        goto done;
    }

    if (oe_posix_unlink_ocall(&ret, full_pathname, &oe_errno) != OE_OK)
    {
        OE_TRACE_ERROR(
            "full_pathname=%s oe_errno =%d", full_pathname, oe_errno);
        goto done;
    }

done:

    return ret;
}

static int _hostfs_rename(
    oe_device_t* fs_,
    const char* oldpath,
    const char* newpath)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    char full_oldpath[OE_PATH_MAX];
    char full_newpath[OE_PATH_MAX];

    if (!fs || !oldpath || !newpath)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = EPERM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (_expand_path(fs, oldpath, full_oldpath) != 0)
    {
        OE_TRACE_ERROR("oldpath=%s full_oldpath=%s", oldpath, full_oldpath);
        goto done;
    }

    if (_expand_path(fs, newpath, full_newpath) != 0)
    {
        OE_TRACE_ERROR("newpath=%s full_newpath=%s", newpath, full_newpath);
        goto done;
    }

    if (oe_posix_rename_ocall(&ret, full_oldpath, full_newpath, &oe_errno) !=
        OE_OK)
    {
        OE_TRACE_ERROR(
            "full_oldpath=%s full_newpath=%s oe_errno =%d",
            full_oldpath,
            full_newpath,
            oe_errno);
        goto done;
    }

done:

    return ret;
}

static int _hostfs_truncate(oe_device_t* fs_, const char* path, oe_off_t length)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    char full_path[OE_PATH_MAX];

    if (!fs)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = EPERM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (_expand_path(fs, path, full_path) != 0)
    {
        OE_TRACE_ERROR("path=%s full_path=%s", path, full_path);
        goto done;
    }

    if (oe_posix_truncate_ocall(&ret, full_path, length, &oe_errno) != OE_OK)
    {
        OE_TRACE_ERROR(
            "full_path=%s length=%lu oe_errno=%d", full_path, length, oe_errno);
        goto done;
    }

done:

    return ret;
}

static int _hostfs_mkdir(oe_device_t* fs_, const char* pathname, oe_mode_t mode)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    char full_pathname[OE_PATH_MAX];

    if (!fs)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = EPERM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (_expand_path(fs, pathname, full_pathname) != 0)
    {
        OE_TRACE_ERROR("pathname=%s full_pathname=%s", pathname, full_pathname);
        goto done;
    }

    if (oe_posix_mkdir_ocall(&ret, full_pathname, mode, &oe_errno) != OE_OK)
    {
        OE_TRACE_ERROR(
            "full_pathname=%s mode=%d oe_errno =%d",
            full_pathname,
            (int)mode,
            oe_errno);
        goto done;
    }

done:

    return ret;
}

static int _hostfs_rmdir(oe_device_t* fs_, const char* pathname)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    char full_pathname[OE_PATH_MAX];

    if (!fs)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = EPERM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (_expand_path(fs, pathname, full_pathname) != 0)
        goto done;

    if (oe_posix_rmdir_ocall(&ret, full_pathname, &oe_errno) != OE_OK)
        goto done;

done:

    return ret;
}

static ssize_t _hostfs_gethostfd(oe_device_t* file_)
{
    file_t* f = _cast_file(file_);

    if (f->magic == FILE_MAGIC)
    {
        return f->host_fd;
    }

    return -1;
}

static oe_fs_ops_t _ops = {
    .base.clone = _hostfs_clone,
    .base.dup = _hostfs_dup,
    .base.release = _hostfs_release,
    .base.shutdown = _hostfs_shutdown,
    .base.ioctl = _hostfs_ioctl,
    .base.fcntl = _hostfs_fcntl,
    .mount = _hostfs_mount,
    .unmount = _hostfs_unmount,
    .open = _hostfs_open,
    .base.read = _hostfs_read,
    .base.write = _hostfs_write,
    .base.get_host_fd = _hostfs_gethostfd,
    .lseek = _hostfs_lseek,
    .base.close = _hostfs_close,
    .getdents = _hostfs_getdents,
    .stat = _hostfs_stat,
    .access = _hostfs_access,
    .link = _hostfs_link,
    .unlink = _hostfs_unlink,
    .rename = _hostfs_rename,
    .truncate = _hostfs_truncate,
    .mkdir = _hostfs_mkdir,
    .rmdir = _hostfs_rmdir,
};

static fs_t _hostfs = {
    .base.type = OE_DEVICE_TYPE_FILESYSTEM,
    .base.name = DEVICE_NAME,
    .base.ops.fs = &_ops,
    .magic = FS_MAGIC,
    .mount_flags = 0,
    .mount_source = {'/'},
};

oe_device_t* oe_get_hostfs_device(void)
{
    return &_hostfs.base;
}

oe_result_t oe_load_module_hostfs(void)
{
    oe_result_t result = OE_FAILURE;
    static bool _loaded = false;
    static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

    if (!_loaded)
    {
        oe_spin_lock(&_lock);

        if (!_loaded)
        {
            const uint64_t devid = OE_DEVID_HOSTFS;

            /* Allocate the device id. */
            if (oe_allocate_devid(devid) != devid)
            {
                OE_TRACE_ERROR("devid=%lu", devid);
                goto done;
            }

            /* Add the hostfs device to the device table. */
            if (oe_set_devid_device(devid, oe_get_hostfs_device()) != 0)
            {
                OE_TRACE_ERROR("devid=%lu", devid);
                goto done;
            }
        }
        oe_spin_unlock(&_lock);
    }
    result = OE_OK;

done:
    return result;
}
