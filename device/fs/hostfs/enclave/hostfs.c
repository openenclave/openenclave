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
#include "../../../common/oe_t.h"
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>

/*
**==============================================================================
**
** host batch:
**
**==============================================================================
*/

static oe_spinlock_t _lock;

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
    file_t* file = NULL;
    char full_pathname[OE_PATH_MAX];
    int retval = -1;

    oe_errno = 0;

    /* Check parameters */
    if (!fs || !pathname)
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

    /* Call */
    {
        int err;

        if (_expand_path(fs, pathname, full_pathname) != 0)
            goto done;

        if (oe_hostfs_open(&retval, full_pathname, flags, mode, &err) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (retval < 0)
        {
            oe_errno = err;
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

static int _hostfs_dup(oe_device_t* file_, oe_device_t** new_file)
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

    /* Call */
    {
        int err = 0;
        int retval = -1;

        if (oe_hostfs_dup(&retval, file->host_fd, &err) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (retval != -1)
        {
            file_t* f = NULL;
            _hostfs_clone(file_, (oe_device_t**)&f);

            if (!f)
            {
                oe_errno = EINVAL;
                goto done;
            }

            f->host_fd = retval;
            *new_file = (oe_device_t*)f;
        }
        else
        {
            oe_errno = err;
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

    /* Check parameters. */
    if (!file || (count && !buf))
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Call the host. */
    if (oe_hostfs_read(&ret, file->host_fd, buf, count, &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
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

static ssize_t _hostfs_write(oe_device_t* file, const void* buf, size_t count)
{
    ssize_t ret = -1;
    file_t* f = _cast_file(file);

    oe_errno = 0;

    /* Check parameters. */
    if (!f || (count && !buf))
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Call the host. */
    if (oe_hostfs_write(&ret, f->host_fd, buf, count, &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

done:
    return ret;
}

static off_t _hostfs_lseek_file(oe_device_t* file, off_t offset, int whence)
{
    off_t ret = -1;
    file_t* f = _cast_file(file);

    oe_errno = 0;

    /* Check parameters. */
    if (!file)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_hostfs_lseek(&ret, f->host_fd, offset, whence, &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
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
        goto done;
    }

    oe_hostfs_rewinddir(dir->host_dir);

    ret = 0;

done:
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

static int _hostfs_close_file(oe_device_t* file)
{
    int ret = -1;
    file_t* f = _cast_file(file);

    oe_errno = 0;

    if (!f)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_hostfs_close(&ret, f->host_fd, &oe_errno) != OE_OK)
    {
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
    dir_t* dir = NULL;
    char full_name[OE_PATH_MAX];
    void* retval = NULL;

    if (!fs || !name)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (_expand_path(fs, name, full_name) != 0)
        goto done;

    if (oe_hostfs_opendir(&retval, full_name, &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

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
        dir->host_dir = retval;
    }

    ret = &dir->base;
    dir = NULL;

done:

    if (dir)
        oe_free(dir);

    return ret;
}

static struct oe_dirent* _hostfs_readdir(oe_device_t* dir)
{
    struct oe_dirent* ret = NULL;
    dir_t* d = _cast_dir(dir);
    int retval = -1;
    struct oe_hostfs_dirent_struct buf;

    if (!d)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_hostfs_readdir(&retval, d->host_dir, &buf, &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (retval == 0)
    {
        d->entry.d_ino = buf.d_ino;
        d->entry.d_off = buf.d_off;
        d->entry.d_reclen = sizeof(struct oe_dirent);
        d->entry.d_type = buf.d_type;
        oe_strlcpy(d->entry.d_name, buf.d_name, sizeof(d->entry.d_name));
        ret = &d->entry;
    }
    else
    {
        memset(&d->entry, 0, sizeof(d->entry));
    }

done:

    return ret;
}

static int _hostfs_closedir(oe_device_t* dir)
{
    int ret = -1;
    dir_t* d = _cast_dir(dir);
    int retval = -1;

    /* Check parameters */
    if (!d)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (oe_hostfs_closedir(&retval, d->host_dir, &oe_errno) != OE_OK)
    {
        oe_errno = EINVAL;
        goto done;
    }

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
    struct oe_hostfs_stat_struct st;
    char full_pathname[OE_PATH_MAX];

    if (buf)
        memset(buf, 0, sizeof(*buf));

    if (!fs || !pathname || !buf)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (_expand_path(fs, pathname, full_pathname) != 0)
        goto done;

    if (oe_hostfs_stat(&ret, full_pathname, &st, &oe_errno) != OE_OK)
    {
        goto done;
    }

    if (ret == 0)
    {
        buf->st_dev = st.st_dev;
        buf->st_ino = st.st_ino;
        buf->st_nlink = st.st_nlink;
        buf->st_mode = st.st_mode;
        buf->st_uid = st.st_uid;
        buf->st_gid = st.st_gid;
        buf->st_rdev = st.st_rdev;
        buf->st_size = st.st_size;
        buf->st_blksize = st.st_blksize;
        buf->st_blocks = st.st_blocks;
        buf->st_atim.tv_sec = st.st_atim.tv_sec;
        buf->st_atim.tv_nsec = st.st_atim.tv_nsec;
        buf->st_mtim.tv_sec = st.st_mtim.tv_sec;
        buf->st_mtim.tv_nsec = st.st_mtim.tv_nsec;
        buf->st_ctim.tv_sec = st.st_ctim.tv_sec;
        buf->st_ctim.tv_nsec = st.st_ctim.tv_nsec;
    }

done:

    return ret;
}

static int _hostfs_access(oe_device_t* fs_, const char* pathname, int mode)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    char full_pathname[OE_PATH_MAX];

    /* Check parameters */
    {
        const uint32_t MASK = (OE_R_OK | OE_W_OK | OE_X_OK);

        if (!fs || !pathname || ((uint32_t)mode & ~MASK))
        {
            oe_errno = EINVAL;
            goto done;
        }
    }

    if (_expand_path(fs, pathname, full_pathname) != 0)
        goto done;

    if (oe_hostfs_access(&ret, full_pathname, mode, &oe_errno) != OE_OK)
        goto done;

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

    /* Check parameters */
    if (!fs || !oldpath || !newpath)
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

    if (_expand_path(fs, oldpath, full_oldpath) != 0)
        goto done;

    if (_expand_path(fs, newpath, full_newpath) != 0)
        goto done;

    if (oe_hostfs_link(&ret, full_oldpath, full_newpath, &oe_errno) != OE_OK)
        goto done;

done:

    return ret;
}

static int _hostfs_unlink(oe_device_t* fs_, const char* pathname)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    char full_pathname[OE_PATH_MAX];

    /* Check parameters */
    if (!fs || !pathname)
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

    if (_expand_path(fs, pathname, full_pathname) != 0)
        goto done;

    if (oe_hostfs_unlink(&ret, full_pathname, &oe_errno) != OE_OK)
        goto done;

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

    /* Check parameters */
    if (!fs || !oldpath || !newpath)
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

    if (_expand_path(fs, oldpath, full_oldpath) != 0)
        goto done;

    if (_expand_path(fs, newpath, full_newpath) != 0)
        goto done;

    if (oe_hostfs_rename(&ret, full_oldpath, full_newpath, &oe_errno) != OE_OK)
        goto done;

done:

    return ret;
}

static int _hostfs_truncate(oe_device_t* fs_, const char* path, off_t length)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    char full_path[OE_PATH_MAX];

    /* Check parameters */
    if (!fs || !path)
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

    if (_expand_path(fs, path, full_path) != 0)
        goto done;

    if (oe_hostfs_truncate(&ret, full_path, length, &oe_errno) != OE_OK)
        goto done;

done:

    return ret;
}

static int _hostfs_mkdir(oe_device_t* fs_, const char* pathname, mode_t mode)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    char full_pathname[OE_PATH_MAX];

    /* Check parameters */
    if (!fs || !pathname)
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

    if (_expand_path(fs, pathname, full_pathname) != 0)
        goto done;

    if (oe_hostfs_mkdir(&ret, full_pathname, mode, &oe_errno) != OE_OK)
        goto done;

done:

    return ret;
}

static int _hostfs_rmdir(oe_device_t* fs_, const char* pathname)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    char full_pathname[OE_PATH_MAX];

    /* Check parameters */
    if (!fs || !pathname)
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

    if (_expand_path(fs, pathname, full_pathname) != 0)
        goto done;

    if (oe_hostfs_rmdir(&ret, full_pathname, &oe_errno) != OE_OK)
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
    .base.dup = _hostfs_dup,
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
