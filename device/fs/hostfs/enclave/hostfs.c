// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE

// clang-format off
#include <openenclave/enclave.h>
// clang-format on

#include <openenclave/internal/device.h>
#include <openenclave/internal/fs_ops.h>
#include <openenclave/internal/fs.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/hostbatch.h>
#include "../common/hostfsargs.h"
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>

/*
**==============================================================================
**
** host batch:
**
**==============================================================================
*/

static oe_host_batch_t* _host_batch;
static oe_spinlock_t _lock;

static void _atexit_handler()
{
    oe_spin_lock(&_lock);
    oe_host_batch_delete(_host_batch);
    _host_batch = NULL;
    oe_spin_unlock(&_lock);
}

static oe_host_batch_t* _get_host_batch(void)
{
    const size_t BATCH_SIZE = sizeof(oe_hostfs_args_t) + OE_BUFSIZ;

    if (_host_batch == NULL)
    {
        oe_spin_lock(&_lock);

        if (_host_batch == NULL)
        {
            _host_batch = oe_host_batch_new(BATCH_SIZE);
            oe_atexit(_atexit_handler);
        }

        oe_spin_unlock(&_lock);
    }

    return _host_batch;
}

/*
**==============================================================================
**
** hostfs operations:
**
**==============================================================================
*/

#define FS_MAGIC 0x5f35f964
#define FILE_MAGIC 0xfe48c6ff
#define DIR_MAGIC 0x8add1b0b

typedef oe_hostfs_args_t args_t;

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
    void* host_dir;
    struct oe_dirent entry;
} dir_t;

static fs_t* _cast_fs(const oe_device_t* device)
{
    fs_t* fs = (fs_t*)device;

    if (fs == NULL || fs->magic != FS_MAGIC)
        return NULL;

    return fs;
}

static file_t* _cast_file(const oe_device_t* device)
{
    file_t* file = (file_t*)device;

    if (file == NULL || file->magic != FILE_MAGIC)
        return NULL;

    return file;
}

static dir_t* _cast_dir(const oe_device_t* device)
{
    dir_t* dir = (dir_t*)device;

    if (dir == NULL || dir->magic != DIR_MAGIC)
        return NULL;

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
            goto done;
        }
    }
    else
    {
        if (oe_strlcpy(path, fs->mount_source, OE_PATH_MAX) >= n)
        {
            oe_errno = ENAMETOOLONG;
            goto done;
        }

        if (!_is_root(suffix))
        {
            if (oe_strlcat(path, "/", OE_PATH_MAX) >= n)
            {
                oe_errno = ENAMETOOLONG;
                goto done;
            }

            if (oe_strlcat(path, suffix, OE_PATH_MAX) >= n)
            {
                oe_errno = ENAMETOOLONG;
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
        goto done;
    }

    if (!(new_fs = oe_calloc(1, sizeof(fs_t))))
    {
        oe_errno = ENOMEM;
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
    mode_t mode)
{
    oe_device_t* ret = NULL;
    fs_t* fs = _cast_fs(fs_);
    args_t* args = NULL;
    file_t* file = NULL;
    oe_host_batch_t* batch = _get_host_batch();

    oe_errno = 0;

    /* Check parameters */
    if (!fs || !pathname || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs) && oe_get_open_access_mode(flags) != OE_O_RDONLY)
    {
        oe_errno = EPERM;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTFS_OP_OPEN;
        args->u.open.ret = -1;

        if (_expand_path(fs, pathname, args->u.open.pathname) != 0)
            goto done;

        args->u.open.flags = flags;
        args->u.open.mode = mode;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTFS, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (args->u.open.ret < 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Output */
    {
        if (!(file = oe_calloc(1, sizeof(file_t))))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        file->base.type = OE_DEVICETYPE_FILE;
        file->base.size = sizeof(file_t);
        file->magic = FILE_MAGIC;
        file->base.ops.fs = fs->base.ops.fs;
        file->host_fd = args->u.open.ret;
    }

    ret = &file->base;
    file = NULL;

done:

    if (file)
        oe_free(file);

    if (args)
        oe_host_batch_free(batch);

    return ret;
}

static oe_device_t* _hostfs_opendir(oe_device_t* fs, const char* name);
static int _hostfs_closedir(oe_device_t* file);

static oe_device_t* _hostfs_open_directory(
    oe_device_t* fs_,
    const char* pathname,
    int flags,
    mode_t mode)
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
        goto done;
    }

    /* Directories can only be opened for read access. */
    if (oe_get_open_access_mode(flags) != OE_O_RDONLY)
    {
        oe_errno = EACCES;
        goto done;
    }

    /* Attempt to open the directory. */
    if (!(dir = _hostfs_opendir(fs_, pathname)))
    {
        goto done;
    }

    /* Allocate and initialize the file struct. */
    {
        if (!(file = oe_calloc(1, sizeof(file_t))))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        file->base.type = OE_DEVICETYPE_FILE;
        file->base.size = sizeof(file_t);
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
    mode_t mode)
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

static ssize_t _hostfs_read(oe_device_t* file_, void* buf, size_t count)
{
    int ret = -1;
    file_t* file = _cast_file(file_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!file || !batch || (count && !buf))
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + count)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTFS_OP_READ;
        args->u.read.ret = -1;
        args->u.read.fd = file->host_fd;
        args->u.read.count = count;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTFS, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.open.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Output */
    {
        memcpy(buf, args->buf, count);
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

    /* Check parameters. */
    if (!file || !file->dir || !dirp)
    {
        oe_errno = EINVAL;
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
                goto done;

            break;
        }

        memcpy(dirp, ent, sizeof(struct oe_dirent));
        bytes += sizeof(struct oe_dirent);
        dirp++;
    }

    ret = bytes;

done:
    return ret;
}

static ssize_t _hostfs_write(oe_device_t* file_, const void* buf, size_t count)
{
    int ret = -1;
    file_t* file = _cast_file(file_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!file || !batch || (count && !buf))
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + count)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTFS_OP_WRITE;
        args->u.write.ret = -1;
        args->u.write.fd = file->host_fd;
        args->u.write.count = count;
        memcpy(args->buf, buf, count);
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTFS, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.open.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

done:
    return ret;
}

static off_t _hostfs_lseek_file(oe_device_t* file_, off_t offset, int whence)
{
    off_t ret = -1;
    file_t* file = _cast_file(file_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!file || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTFS_OP_LSEEK;
        args->u.lseek.ret = -1;
        args->u.lseek.fd = file->host_fd;
        args->u.lseek.offset = offset;
        args->u.lseek.whence = whence;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTFS, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.lseek.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

done:
    return ret;
}

static int _hostfs_rewinddir(oe_device_t* dir_)
{
    int ret = -1;
    dir_t* dir = _cast_dir(dir_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    /* Check parameters */
    if (!dir || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
            goto done;

        args->op = OE_HOSTFS_OP_REWINDDIR;
        args->u.rewinddir.dirp = dir->host_dir;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTFS, (uint64_t)args, NULL) != OE_OK)
            goto done;
    }

done:

    if (args)
        oe_host_batch_free(batch);

    return ret;
}

static off_t _hostfs_lseek_dir(oe_device_t* file_, off_t offset, int whence)
{
    off_t ret = -1;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    /* Check parameters. */
    if (!file || !file->dir || offset != 0 || whence != OE_SEEK_SET)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (_hostfs_rewinddir(file->dir) != 0)
    {
        goto done;
    }

    ret = 0;

done:
    return ret;
}

static off_t _hostfs_lseek(oe_device_t* file_, off_t offset, int whence)
{
    off_t ret = -1;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    /* Check parameters. */
    if (!file)
    {
        oe_errno = EINVAL;
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
    return ret;
}

static int _hostfs_close_file(oe_device_t* file_)
{
    int ret = -1;
    file_t* file = _cast_file(file_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!file || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTFS_OP_CLOSE;
        args->u.close.ret = -1;
        args->u.close.fd = file->host_fd;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTFS, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (args->u.close.ret != 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Release the file object. */
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
        goto done;
    }

    /* Release the directory object. */
    if (_hostfs_closedir(file->dir) != 0)
        goto done;

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
    oe_device_t* file,
    unsigned long request,
    oe_va_list ap)
{
    /* Unsupported */
    oe_errno = ENOTTY;
    (void)file;
    (void)request;
    (void)ap;
    return -1;
}

static oe_device_t* _hostfs_opendir(oe_device_t* fs_, const char* name)
{
    oe_device_t* ret = NULL;
    fs_t* fs = _cast_fs(fs_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;
    dir_t* dir = NULL;

    /* Check parameters */
    if (!fs || !name || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTFS_OP_OPENDIR;
        args->u.opendir.ret = NULL;

        if (_expand_path(fs, name, args->u.opendir.name) != 0)
            goto done;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTFS, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (args->u.opendir.ret == NULL)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Output */
    {
        if (!(dir = oe_calloc(1, sizeof(dir_t))))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        dir->base.type = OE_DEVICETYPE_DIRECTORY;
        dir->base.size = sizeof(dir_t);
        dir->magic = DIR_MAGIC;
        dir->base.ops.fs = fs->base.ops.fs;
        dir->host_dir = args->u.opendir.ret;
    }

    ret = &dir->base;
    dir = NULL;

done:

    if (args)
        oe_host_batch_free(batch);

    if (dir)
        oe_free(dir);

    return ret;
}

static struct oe_dirent* _hostfs_readdir(oe_device_t* dir_)
{
    struct oe_dirent* ret = NULL;
    dir_t* dir = _cast_dir(dir_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    /* Check parameters */
    if (!dir || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
            goto done;

        args->u.readdir.ret = NULL;
        args->op = OE_HOSTFS_OP_READDIR;
        args->u.readdir.dirp = dir->host_dir;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTFS, (uint64_t)args, NULL) != OE_OK)
            goto done;

        if (!args->u.readdir.ret)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Output */
    if (args->u.readdir.ret)
    {
        dir->entry = args->u.readdir.entry;
        dir->entry.d_reclen = sizeof(struct oe_dirent);
        ret = &dir->entry;
    }

done:

    if (args)
        oe_host_batch_free(batch);

    return ret;
}

static int _hostfs_closedir(oe_device_t* dir_)
{
    int ret = -1;
    dir_t* dir = _cast_dir(dir_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    /* Check parameters */
    if (!dir || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
            goto done;

        args->op = OE_HOSTFS_OP_CLOSEDIR;
        args->u.closedir.ret = -1;
        args->u.closedir.dirp = dir->host_dir;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTFS, (uint64_t)args, NULL) != OE_OK)
            goto done;

        if ((ret = args->u.closedir.ret) != 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    oe_free(dir);

done:

    if (args)
        oe_host_batch_free(batch);

    return ret;
}

static int _hostfs_stat(
    oe_device_t* fs_,
    const char* pathname,
    struct oe_stat* buf)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    /* Check parameters */
    if (!fs || !pathname || !buf || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
            goto done;

        args->op = OE_HOSTFS_OP_STAT;
        args->u.stat.ret = -1;

        if (_expand_path(fs, pathname, args->u.stat.pathname) != 0)
            goto done;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTFS, (uint64_t)args, NULL) != OE_OK)
            goto done;

        if ((ret = args->u.stat.ret) != 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Output */
    {
        *buf = args->u.stat.buf;
    }

done:

    if (args)
        oe_host_batch_free(batch);

    return ret;
}

static int _hostfs_access(oe_device_t* fs_, const char* pathname, int mode)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    /* Check parameters */
    {
        const uint32_t MASK = (OE_R_OK | OE_W_OK | OE_X_OK);

        if (!fs || !pathname || ((uint32_t)mode & ~MASK))
        {
            oe_errno = EINVAL;
            goto done;
        }
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
            goto done;

        args->op = OE_HOSTFS_OP_ACCESS;
        args->u.access.ret = -1;
        args->u.access.mode = mode;

        if (_expand_path(fs, pathname, args->u.access.pathname) != 0)
            goto done;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTFS, (uint64_t)args, NULL) != OE_OK)
            goto done;

        if ((ret = args->u.stat.ret) != 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

done:

    if (args)
        oe_host_batch_free(batch);

    return ret;
}

static int _hostfs_link(
    oe_device_t* fs_,
    const char* oldpath,
    const char* newpath)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    /* Check parameters */
    if (!fs || !oldpath || !newpath || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = EPERM;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
            goto done;

        args->op = OE_HOSTFS_OP_LINK;
        args->u.link.ret = -1;

        if (_expand_path(fs, oldpath, args->u.link.oldpath) != 0)
            goto done;

        if (_expand_path(fs, newpath, args->u.link.newpath) != 0)
            goto done;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTFS, (uint64_t)args, NULL) != OE_OK)
            goto done;

        if ((ret = args->u.link.ret) != 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

done:

    if (args)
        oe_host_batch_free(batch);

    return ret;
}

static int _hostfs_unlink(oe_device_t* fs_, const char* pathname)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    /* Check parameters */
    if (!fs || !pathname || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = EPERM;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
            goto done;

        args->op = OE_HOSTFS_OP_UNLINK;
        args->u.unlink.ret = -1;

        if (_expand_path(fs, pathname, args->u.unlink.pathname) != 0)
            goto done;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTFS, (uint64_t)args, NULL) != OE_OK)
            goto done;

        if ((ret = args->u.unlink.ret) != 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

done:

    if (args)
        oe_host_batch_free(batch);

    return ret;
}

static int _hostfs_rename(
    oe_device_t* fs_,
    const char* oldpath,
    const char* newpath)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    /* Check parameters */
    if (!fs || !oldpath || !newpath || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = EPERM;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
            goto done;

        args->op = OE_HOSTFS_OP_RENAME;
        args->u.rename.ret = -1;

        if (_expand_path(fs, oldpath, args->u.rename.oldpath) != 0)
            goto done;

        if (_expand_path(fs, newpath, args->u.rename.newpath) != 0)
            goto done;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTFS, (uint64_t)args, NULL) != OE_OK)
            goto done;

        if ((ret = args->u.rename.ret) != 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

done:

    if (args)
        oe_host_batch_free(batch);

    return ret;
}

static int _hostfs_truncate(oe_device_t* fs_, const char* path, off_t length)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    /* Check parameters */
    if (!fs || !path || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = EPERM;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
            goto done;

        args->op = OE_HOSTFS_OP_TRUNCATE;
        args->u.truncate.ret = -1;
        args->u.truncate.length = length;

        if (_expand_path(fs, path, args->u.truncate.path) != 0)
            goto done;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTFS, (uint64_t)args, NULL) != OE_OK)
            goto done;

        if ((ret = args->u.truncate.ret) != 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

done:

    if (args)
        oe_host_batch_free(batch);

    return ret;
}

static int _hostfs_mkdir(oe_device_t* fs_, const char* pathname, mode_t mode)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    /* Check parameters */
    if (!fs || !pathname || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = EPERM;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
            goto done;

        args->op = OE_HOSTFS_OP_MKDIR;
        args->u.mkdir.ret = -1;
        args->u.mkdir.mode = mode;

        if (_expand_path(fs, pathname, args->u.mkdir.pathname) != 0)
            goto done;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTFS, (uint64_t)args, NULL) != OE_OK)
            goto done;

        if ((ret = args->u.mkdir.ret) != 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

done:

    if (args)
        oe_host_batch_free(batch);

    return ret;
}

static int _hostfs_rmdir(oe_device_t* fs_, const char* pathname)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    /* Check parameters */
    if (!fs || !pathname || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = EPERM;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
            goto done;

        args->op = OE_HOSTFS_OP_RMDIR;
        args->u.rmdir.ret = -1;

        if (_expand_path(fs, pathname, args->u.rmdir.pathname) != 0)
            goto done;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTFS, (uint64_t)args, NULL) != OE_OK)
            goto done;

        if ((ret = args->u.rmdir.ret) != 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

done:

    if (args)
        oe_host_batch_free(batch);

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

static uint64_t _hostfs_readystate(oe_device_t* file_)
{
    file_t* f = _cast_file(file_);

    if (f->magic == FILE_MAGIC)
    {
        return f->ready_mask;
    }
    return (uint64_t)-1; // Invalid value
}

static oe_fs_ops_t _ops = {
    .base.clone = _hostfs_clone,
    .base.release = _hostfs_release,
    .base.shutdown = _hostfs_shutdown,
    .base.ioctl = _hostfs_ioctl,
    .mount = _hostfs_mount,
    .unmount = _hostfs_unmount,
    .open = _hostfs_open,
    .base.read = _hostfs_read,
    .base.write = _hostfs_write,
    .base.get_host_fd = _hostfs_gethostfd,
    .base.ready_state = _hostfs_readystate,
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
    .base.type = OE_DEVICETYPE_FILESYSTEM,
    .base.size = sizeof(fs_t),
    .base.ops.fs = &_ops,
    .magic = FS_MAGIC,
    .mount_flags = 0,
    .mount_source = {'/'},
};

oe_device_t* oe_fs_get_hostfs(void)
{
    return &_hostfs.base;
}

int oe_register_hostfs_device(void)
{
    int ret = -1;
    const uint64_t devid = OE_DEVID_HOSTFS;

    /* Allocate the device id. */
    if (oe_allocate_devid(devid) != devid)
        goto done;

    /* Add the hostfs device to the device table. */
    if (oe_set_devid_device(devid, oe_fs_get_hostfs()) != 0)
        goto done;

    ret = 0;

done:
    return ret;
}
