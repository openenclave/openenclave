// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include "linux-sgx/common/inc/sgx_tprotected_fs.h"
// clang-format on

/* ATTN:IO: use elibc within SGX code. */
#include <errno.h>
#include <openenclave/enclave.h>
#include <openenclave/bits/sgxfs.h>
#include <openenclave/internal/print.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/fcntl.h>
#include <openenclave/internal/thread.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/posix/device.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/bits/safecrt.h>

#define FS_MAGIC 0x4a335f60
#define FILE_MAGIC 0x8d7e422f
#define DIR_MAGIC 0xc1bfdfa4

extern oe_device_t* oe_get_hostfs_device(void);

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
    SGX_FILE* stream;
} file_t;

static int _get_open_access_mode(int flags)
{
    return (flags & 000000003);
}

static fs_t* _cast_fs(const oe_device_t* device)
{
    fs_t* fs = (fs_t*)device;

    if (fs == NULL || fs->magic != FS_MAGIC)
        return NULL;

    return fs;
}

OE_INLINE bool _is_rdonly(const fs_t* fs)
{
    return fs->mount_flags & OE_MS_RDONLY;
}

static char* _strrchr(const char* s, char c)
{
    char* ret = NULL;

    while (*s)
    {
        if (*s == c)
            ret = (char*)s;

        s++;
    }

    return ret;
}

static file_t* _cast_file(const oe_device_t* device)
{
    file_t* file = (file_t*)device;

    if (file == NULL || file->magic != FILE_MAGIC)
        return NULL;

    return file;
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
            OE_RAISE_ERRNO(OE_ENAMETOOLONG);
    }
    else
    {
        if (oe_strlcpy(path, fs->mount_source, OE_PATH_MAX) >= n)
            OE_RAISE_ERRNO(OE_ENAMETOOLONG);

        if (!_is_root(suffix))
        {
            if (oe_strlcat(path, "/", OE_PATH_MAX) >= n)
                OE_RAISE_ERRNO(OE_ENAMETOOLONG);

            if (oe_strlcat(path, suffix, OE_PATH_MAX) >= n)
                OE_RAISE_ERRNO(OE_ENAMETOOLONG);
        }
    }

    ret = 0;

done:
    return ret;
}

static int _split_path(
    const char* path,
    char dirname[OE_PATH_MAX],
    char basename[OE_PATH_MAX])
{
    int ret = -1;
    char* slash;

    /* Reject paths that are too long. */
    if (oe_strlen(path) >= OE_PATH_MAX)
        OE_RAISE_ERRNO(OE_ENAMETOOLONG);

    /* Reject paths that are not absolute */
    if (path[0] != '/')
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Handle root directory up front */
    if (oe_strcmp(path, "/") == 0)
    {
        oe_strlcpy(dirname, "/", OE_PATH_MAX);
        oe_strlcpy(basename, "/", OE_PATH_MAX);
        ret = 0;
        goto done;
    }

    /* This cannot fail (prechecked) */
    if (!(slash = _strrchr(path, '/')))
        OE_RAISE_ERRNO(OE_EINVAL);

    /* If path ends with '/' character */
    if (!slash[1])
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Split the path */
    {
        if (slash == path)
        {
            oe_strlcpy(dirname, "/", OE_PATH_MAX);
        }
        else
        {
            int64_t index = slash - path;
            oe_strlcpy(dirname, path, OE_PATH_MAX);

            if (index < OE_PATH_MAX)
                dirname[index] = '\0';
            else
                dirname[OE_PATH_MAX - 1] = '\0';
        }

        oe_strlcpy(basename, slash + 1, OE_PATH_MAX);
    }

    ret = 0;

done:
    return ret;
}

static int _sgxfs_mount(
    oe_device_t* dev,
    const char* source,
    const char* target,
    unsigned long flags)
{
    int ret = -1;
    fs_t* fs = _cast_fs(dev);

    OE_UNUSED(source);
    OE_UNUSED(flags);

    if (!fs || !source || !target)
        OE_RAISE_ERRNO(OE_EINVAL);

    fs->mount_flags = flags;
    oe_strlcpy(fs->mount_source, source, sizeof(fs->mount_source));

    ret = 0;

done:
    return ret;
}

static int _sgxfs_unmount(oe_device_t* dev, const char* target)
{
    int ret = -1;
    fs_t* fs = _cast_fs(dev);

    if (!fs || !target)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = 0;

done:
    return ret;
}

static int _sgxfs_clone(oe_device_t* device, oe_device_t** new_device)
{
    int ret = -1;
    fs_t* fs = _cast_fs(device);
    fs_t* new_fs = NULL;

    if (!fs || !new_device)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(new_fs = oe_calloc(1, sizeof(fs_t))))
        OE_RAISE_ERRNO(OE_ENOMEM);

    *new_fs = *fs;
    *new_device = &new_fs->base;
    ret = 0;

done:
    return ret;
}

static int _sgxfs_release(oe_device_t* device)
{
    int ret = -1;
    fs_t* fs = _cast_fs(device);

    if (!fs)
        OE_RAISE_ERRNO(OE_EINVAL);

    oe_free(fs);
    ret = 0;

done:
    return ret;
}

static int _sgxfs_shutdown(oe_device_t* device)
{
    int ret = -1;
    fs_t* fs = _cast_fs(device);

    if (!fs)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = 0;

done:
    return ret;
}

static oe_device_t* _sgxfs_open_file(
    oe_device_t* fs_,
    const char* pathname,
    int flags,
    oe_mode_t mode)
{
    oe_device_t* ret = NULL;
    fs_t* fs = _cast_fs(fs_);
    file_t* file = NULL;
    const char* fopen_mode = NULL;
    SGX_FILE* stream = NULL;

    oe_errno = 0;

    (void)mode;

    /* Check parameters */
    if (!fs || !pathname)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs) && _get_open_access_mode(flags) != OE_O_RDONLY)
        OE_RAISE_ERRNO(OE_EPERM);

    /* Nonblocking I/O is unsupported. */
    if ((flags & OE_O_NONBLOCK))
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Convert the flags to an fopen-mode string. */
    switch ((flags & 0x00000003))
    {
        case OE_O_RDONLY:
        {
            fopen_mode = "r";
            break;
        }
        case OE_O_RDWR:
        {
            if (flags & OE_O_CREAT)
            {
                if (flags & OE_O_TRUNC)
                {
                    fopen_mode = "w+";
                }
                else if (flags & OE_O_APPEND)
                {
                    fopen_mode = "a+";
                }
                else
                {
                    OE_RAISE_ERRNO(OE_EINVAL);
                }
            }
            else
            {
                fopen_mode = "r+";
            }
            break;
        }
        case OE_O_WRONLY:
        {
            if (flags & OE_O_CREAT)
            {
                if (flags & OE_O_TRUNC)
                {
                    fopen_mode = "w";
                }
                else if (flags & OE_O_APPEND)
                {
                    fopen_mode = "a";
                }
                else
                {
                    OE_RAISE_ERRNO(OE_EINVAL);
                }
            }
            else
            {
                fopen_mode = "w";
            }
            break;
        }
        default:
        {
            OE_RAISE_ERRNO(OE_EINVAL);
        }
    }

    /* Open the protected file. */
    {
        char full_path[OE_PATH_MAX];

        if (_expand_path(fs, pathname, full_path) != 0)
            OE_RAISE_ERRNO(oe_errno);

        if (!(stream = sgx_fopen_auto_key(full_path, fopen_mode)))
            goto done;
    }

    /* Allocate and initialize file struct. */
    {
        if (!(file = oe_calloc(1, sizeof(file_t))))
            OE_RAISE_ERRNO(OE_ENOMEM);

        file->base.type = OE_DEVICE_TYPE_FILE;
        file->base.name = OE_DEVICE_NAME_SGX_FILE_SYSTEM;
        file->magic = FILE_MAGIC;
        file->base.ops.fs = fs->base.ops.fs;
        file->stream = stream;
    }

    ret = &file->base;
    file = NULL;
    stream = NULL;

done:

    if (file)
    {
        oe_memset_s(file, sizeof(file_t), 0xDD, sizeof(file_t));
        oe_free(file);
    }

    if (stream)
        sgx_fclose(stream);

    return ret;
}

static oe_device_t* _sgxfs_open_directory(
    oe_device_t* fs_,
    const char* pathname,
    int flags,
    oe_mode_t mode)
{
    oe_device_t* ret = NULL;
    fs_t* fs = _cast_fs(fs_);
    oe_device_t* hostfs = oe_get_hostfs_device();

    if (!fs || !hostfs)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Delegate the request to HOSTFS. */
    {
        char full_path[OE_PATH_MAX];

        if (_expand_path(fs, pathname, full_path) != 0)
            OE_RAISE_ERRNO(oe_errno);

        ret = OE_CALL_FS(open, hostfs, full_path, flags, mode);
    }

done:

    return ret;
}

static oe_device_t* _sgxfs_open(
    oe_device_t* fs,
    const char* pathname,
    int flags,
    oe_mode_t mode)
{
    if ((flags & OE_O_DIRECTORY))
    {
        return _sgxfs_open_directory(fs, pathname, flags, mode);
    }
    else
    {
        return _sgxfs_open_file(fs, pathname, flags, mode);
    }
}

static ssize_t _sgxfs_read(oe_device_t* file_, void* buf, size_t count)
{
    ssize_t ret = -1;
    size_t n;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    if (!file || (count && !buf))
        OE_RAISE_ERRNO(OE_EINVAL);

    if ((n = sgx_fread(buf, 1, count, file->stream)) == 0)
    {
        if (!sgx_feof(file->stream))
            OE_RAISE_ERRNO(sgx_ferror(file->stream));
    }

    ret = (ssize_t)n;

done:
    return ret;
}

static ssize_t _sgxfs_write(oe_device_t* file_, const void* buf, size_t count)
{
    ssize_t ret = -1;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    if (!file || (count && !buf))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (sgx_fwrite(buf, 1, count, file->stream) != count)
        OE_RAISE_ERRNO(sgx_ferror(file->stream));

    ret = (ssize_t)count;

done:
    return ret;
}

static oe_off_t _sgxfs_lseek(oe_device_t* file_, oe_off_t offset, int whence)
{
    oe_off_t ret = -1;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (sgx_fseek(file->stream, offset, whence) != 0)
        OE_RAISE_ERRNO(oe_errno);

    ret = sgx_ftell(file->stream);

done:
    return ret;
}

static int _sgxfs_close_file(oe_device_t* file_)
{
    int ret = -1;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (sgx_fclose(file->stream) != 0)
        OE_RAISE_ERRNO(OE_EBADF);

    oe_memset_s(file, sizeof(file_t), 0xDD, sizeof(file_t));
    oe_free(file);

    ret = 0;

done:
    return ret;
}

static int _sgxfs_close(oe_device_t* file_)
{
    int ret = -1;
    file_t* file = _cast_file(file_);
    oe_device_t* hostfs = oe_get_hostfs_device();

    if (!hostfs)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (file)
    {
        if (_sgxfs_close_file(file_) != 0)
            OE_RAISE_ERRNO(oe_errno);
    }
    else
    {
        if (OE_CALL_BASE(close, file_) != 0)
            OE_RAISE_ERRNO(oe_errno);
    }

    ret = 0;

done:
    return ret;
}

static int _sgxfs_ioctl(oe_device_t* file, unsigned long request, uint64_t arg)
{
    OE_UNUSED(file);
    OE_UNUSED(request);
    OE_UNUSED(arg);

    oe_errno = ENOTSUP;
    return -1;
}

static int _sgxfs_fcntl(oe_device_t* file, int cmd, uint64_t arg)
{
    /* Unsupported */
    OE_UNUSED(file);
    OE_UNUSED(cmd);
    OE_UNUSED(arg);

    oe_errno = ENOTSUP;
    return -1;
}

static int _sgxfs_getdents(
    oe_device_t* file,
    struct oe_dirent* dirp,
    unsigned int count)
{
    int ret = -1;
    int n;
    oe_device_t* hostfs = oe_get_hostfs_device();

    if (!hostfs)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Delegate the request to HOSTFS. */
    if ((n = OE_CALL_FS(getdents, file, dirp, count)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    ret = n;

done:

    return ret;
}

static int _sgxfs_stat(
    oe_device_t* fs_,
    const char* pathname,
    struct oe_stat* buf)
{
    int ret = -1;
    SGX_FILE* stream = NULL;
    fs_t* fs = _cast_fs(fs_);
    oe_device_t* hostfs = oe_get_hostfs_device();

    OE_UNUSED(fs_);

    if (!fs || !hostfs)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Ask HOSTFS to stat the directory. */
    {
        char full_path[OE_PATH_MAX];
        int r;

        if (_expand_path(fs, pathname, full_path) != 0)
            OE_RAISE_ERRNO(oe_errno);

        if ((r = OE_CALL_FS(stat, hostfs, full_path, buf)) == -1)
        {
            ret = r;
            goto done;
        }
    }

    /* Recalculate the size to omit the metadata headers. */
    if (!OE_S_ISDIR(buf->st_mode))
    {
        int64_t offset;
        char full_path[OE_PATH_MAX];

        if (_expand_path(fs, pathname, full_path) != 0)
            OE_RAISE_ERRNO(oe_errno);

        if (!(stream = sgx_fopen_auto_key(full_path, "r")))
            OE_RAISE_ERRNO(oe_errno);

        if (sgx_fseek(stream, 0L, SEEK_END) != 0)
            OE_RAISE_ERRNO(oe_errno);

        if ((offset = sgx_ftell(stream)) < 0)
            OE_RAISE_ERRNO(oe_errno);

        buf->st_size = (oe_off_t)offset;
    }

    ret = 0;

done:

    if (stream)
        sgx_fclose(stream);

    return ret;
}

static int _sgxfs_access(oe_device_t* fs_, const char* pathname, int mode)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    oe_device_t* hostfs = oe_get_hostfs_device();

    OE_UNUSED(fs_);

    if (!fs || !hostfs)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Delegate the request to HOSTFS. */
    {
        char full_path[OE_PATH_MAX];

        if (_expand_path(fs, pathname, full_path) != 0)
            OE_RAISE_ERRNO(oe_errno);

        if ((ret = OE_CALL_FS(access, hostfs, full_path, mode)) != 0)
            OE_RAISE_ERRNO(oe_errno);
    }

    ret = 0;

done:

    return ret;
}

static int _sgxfs_link(
    oe_device_t* fs_,
    const char* oldpath,
    const char* newpath)
{
    fs_t* fs = _cast_fs(fs_);
    int ret = -1;
    SGX_FILE* in = NULL;
    SGX_FILE* out = NULL;
    char buf[OE_BUFSIZ];
    size_t n;

    if (!fs || !oldpath || !newpath)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
        OE_RAISE_ERRNO(EPERM);

    /* Open the input file. */
    {
        char full_path[OE_PATH_MAX];

        if (_expand_path(fs, oldpath, full_path) != 0)
            OE_RAISE_ERRNO(oe_errno);

        if (!(in = sgx_fopen_auto_key(full_path, "r")))
            OE_RAISE_ERRNO(oe_errno);
    }

    /* Open the output file. */
    {
        char full_path[OE_PATH_MAX];

        if (_expand_path(fs, newpath, full_path) != 0)
            OE_RAISE_ERRNO(oe_errno);

        if (!(out = sgx_fopen_auto_key(full_path, "w")))
            OE_RAISE_ERRNO(oe_errno);
    }

    /* Copy the file. */
    while ((n = sgx_fread(buf, 1, sizeof(buf), in)) > 0)
    {
        if (sgx_fwrite(buf, 1, n, out) != n)
            OE_RAISE_ERRNO(sgx_ferror(out));
    }

    ret = 0;

done:

    if (in)
        sgx_fclose(in);

    if (out)
        sgx_fclose(out);

    return ret;
}

static int _sgxfs_unlink(oe_device_t* fs_, const char* pathname)
{
    int ret = -1;
    oe_device_t* hostfs = oe_get_hostfs_device();
    fs_t* fs = _cast_fs(fs_);

    if (!fs || !hostfs)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
        OE_RAISE_ERRNO(OE_EPERM);

    /* Delegate unlink operation to HOSTFS. */
    {
        char full_path[OE_PATH_MAX];

        if (_expand_path(fs, pathname, full_path) != 0)
            OE_RAISE_ERRNO(oe_errno);

        ret = OE_CALL_FS(unlink, hostfs, full_path);
    }

done:
    return ret;
}

static int _sgxfs_rename(
    oe_device_t* fs_,
    const char* oldpath,
    const char* newpath)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    SGX_FILE* in = NULL;
    SGX_FILE* out = NULL;
    char buf[OE_BUFSIZ];
    size_t n;
    oe_device_t* hostfs = oe_get_hostfs_device();

    if (!fs || !hostfs || !oldpath || !newpath)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
        OE_RAISE_ERRNO(OE_EPERM);

    /* Open the input file. */
    {
        char full_path[OE_PATH_MAX];

        if (_expand_path(fs, oldpath, full_path) != 0)
            OE_RAISE_ERRNO(oe_errno);

        if (!(in = sgx_fopen_auto_key(full_path, "r")))
            OE_RAISE_ERRNO(oe_errno);
    }

    /* Open the output file. */
    {
        char full_path[OE_PATH_MAX];

        if (_expand_path(fs, newpath, full_path) != 0)
            OE_RAISE_ERRNO(oe_errno);

        if (!(out = sgx_fopen_auto_key(full_path, "w")))
            OE_RAISE_ERRNO(oe_errno);
    }

    /* Copy the file. */
    while ((n = sgx_fread(buf, 1, sizeof(buf), in)) > 0)
    {
        if (sgx_fwrite(buf, 1, n, out) != n)
            OE_RAISE_ERRNO(sgx_ferror(out));
    }

    /* Delegate file removal to the HOSTFS. */
    {
        char full_path[OE_PATH_MAX];

        if (_expand_path(fs, oldpath, full_path) != 0)
            OE_RAISE_ERRNO(oe_errno);

        if (OE_CALL_FS(unlink, hostfs, full_path) != 0)
            OE_RAISE_ERRNO(oe_errno);
    }

    ret = 0;

done:

    if (in)
        sgx_fclose(in);

    if (out)
        sgx_fclose(out);

    return ret;
}

static int _sgxfs_truncate(oe_device_t* fs_, const char* path, oe_off_t length)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    size_t remaining = (size_t)length;
    char dirname[OE_PAGE_SIZE];
    char basename[OE_PAGE_SIZE];
    char tmp_file[OE_PAGE_SIZE];
    SGX_FILE* in = NULL;
    SGX_FILE* out = NULL;
    size_t n;
    char buf[OE_BUFSIZ];
    bool remove_tmp_file = false;

    if (!fs || !path || length < 0)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
        OE_RAISE_ERRNO(OE_EPERM);

    /* Form the name of a temporary file. */
    {
        const size_t n = sizeof(tmp_file);

        if (_split_path(path, dirname, basename) != 0)
            OE_RAISE_ERRNO(oe_errno);

        if (oe_strlcpy(tmp_file, dirname, n) >= n)
            OE_RAISE_ERRNO(OE_EINVAL);

        if (oe_strlcat(tmp_file, "/.", n) >= n)
            OE_RAISE_ERRNO(OE_EINVAL);

        if (oe_strlcat(tmp_file, basename, n) >= n)
            OE_RAISE_ERRNO(OE_EINVAL);

        if (oe_strlcat(tmp_file, ".sgxfs.truncate", n) >= n)
            OE_RAISE_ERRNO(OE_EINVAL);
    }

    /* Create a temporary copy of this file. */
    if (_sgxfs_link(fs_, path, tmp_file) != 0)
    {
        remove_tmp_file = true;
        OE_RAISE_ERRNO(oe_errno);
    }

    /* Open the input file. */
    {
        char full_path[OE_PATH_MAX];

        if (_expand_path(fs, tmp_file, full_path) != 0)
            OE_RAISE_ERRNO(oe_errno);

        if (!(in = sgx_fopen_auto_key(full_path, "r")))
            OE_RAISE_ERRNO(oe_errno);
    }

    /* Open and truncate the output file. */
    {
        char full_path[OE_PATH_MAX];

        if (_expand_path(fs, path, full_path) != 0)
            OE_RAISE_ERRNO(oe_errno);

        if (!(out = sgx_fopen_auto_key(full_path, "w")))
            OE_RAISE_ERRNO(oe_errno);
    }

    /* Copy length bytes from the input file to the output file. */
    while (remaining && (n = sgx_fread(buf, 1, sizeof(buf), in)) > 0)
    {
        if (n > remaining)
            n = remaining;

        if (sgx_fwrite(buf, 1, n, out) != n)
            OE_RAISE_ERRNO(sgx_ferror(out));

        remaining -= n;
    }

    ret = 0;

done:

    if (remove_tmp_file)
        _sgxfs_unlink(fs_, tmp_file);

    if (in)
        sgx_fclose(in);

    if (out)
        sgx_fclose(out);

    return ret;
}

static int _sgxfs_mkdir(oe_device_t* fs_, const char* pathname, oe_mode_t mode)
{
    int ret = -1;
    oe_device_t* hostfs = oe_get_hostfs_device();
    fs_t* fs = _cast_fs(fs_);

    if (!fs || !hostfs)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
        OE_RAISE_ERRNO(OE_EPERM);

    /* Delegate directory creation to HOSTFS. */
    {
        char full_path[OE_PATH_MAX];

        if (_expand_path(fs, pathname, full_path) != 0)
            OE_RAISE_ERRNO(oe_errno);

        if (OE_CALL_FS(mkdir, hostfs, full_path, mode) != 0)
            OE_RAISE_ERRNO(oe_errno);
    }

    ret = 0;

done:
    return ret;
}

static int _sgxfs_rmdir(oe_device_t* fs_, const char* pathname)
{
    int ret = -1;
    oe_device_t* hostfs = oe_get_hostfs_device();
    fs_t* fs = _cast_fs(fs_);

    if (!fs || !hostfs)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
        OE_RAISE_ERRNO(OE_EPERM);

    /* Delegate directory removal to HOSTFS. */
    {
        char full_path[OE_PATH_MAX];

        if (_expand_path(fs, pathname, full_path) != 0)
            OE_RAISE_ERRNO(oe_errno);

        ret = OE_CALL_FS(rmdir, hostfs, full_path);
    }

done:
    return ret;
}

static oe_fs_ops_t _ops = {
    .base.shutdown = _sgxfs_shutdown,
    .base.ioctl = _sgxfs_ioctl,
    .base.fcntl = _sgxfs_fcntl,
    .clone = _sgxfs_clone,
    .release = _sgxfs_release,
    .mount = _sgxfs_mount,
    .unmount = _sgxfs_unmount,
    .open = _sgxfs_open,
    .base.read = _sgxfs_read,
    .base.write = _sgxfs_write,
    .lseek = _sgxfs_lseek,
    .base.close = _sgxfs_close,
    .getdents = _sgxfs_getdents,
    .stat = _sgxfs_stat,
    .access = _sgxfs_access,
    .link = _sgxfs_link,
    .unlink = _sgxfs_unlink,
    .rename = _sgxfs_rename,
    .truncate = _sgxfs_truncate,
    .mkdir = _sgxfs_mkdir,
    .rmdir = _sgxfs_rmdir,
};

static fs_t _sgxfs = {
    .base.type = OE_DEVICE_TYPE_FILESYSTEM,
    .base.name = OE_DEVICE_NAME_SGX_FILE_SYSTEM,
    .base.ops.fs = &_ops,
    .magic = FS_MAGIC,
};

static oe_device_t* _get_sgxfs_device(void)
{
    return &_sgxfs.base;
}

static oe_once_t _once = OE_ONCE_INITIALIZER;
static bool _loaded;

static void _load_once()
{
    oe_result_t result = OE_FAILURE;
    const uint64_t devid = OE_DEVID_SGX_FILE_SYSTEM;

    if (oe_set_device(devid, _get_sgxfs_device()) != 0)
        OE_RAISE_ERRNO(OE_EINVAL);

    result = OE_OK;

done:

    if (result == OE_OK)
        _loaded = true;
}

oe_result_t oe_load_module_sgxfs(void)
{
    if (oe_once(&_once, _load_once) != OE_OK || !_loaded)
        return OE_FAILURE;

    return OE_OK;
}
