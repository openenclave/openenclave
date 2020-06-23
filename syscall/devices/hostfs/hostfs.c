// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/*
**==============================================================================
**
** hostfs:
**
**     This module implements the host file system, which allows enclaves to
**     manipulate non-secure host files. To use this module, the enclave
**     application must:
**
**     (1) Link the oehostfs library.
**     (2) Load the module by calling oe_load_module_host_file_system().
**     (3) Use the standard C file I/O functions (e.g., open, read, write).
**
**==============================================================================
*/

// clang-format off
#include <openenclave/enclave.h>
// clang-format on

#include <openenclave/internal/syscall/device.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/syscall/dirent.h>
#include <openenclave/internal/syscall/sys/mount.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/syscall/fcntl.h>
#include <openenclave/internal/syscall/sys/ioctl.h>
#include <openenclave/internal/syscall/raise.h>
#include <openenclave/internal/syscall/iov.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/safecrt.h>

#include "syscall_t.h"

#define FS_MAGIC 0x5f35f964
#define FILE_MAGIC 0xfe48c6ff
#define DIR_MAGIC 0x8add1b0b

/* Mask to extract the access mode: O_RDONLY, O_WRONLY, O_RDWR. */
#define ACCESS_MODE_MASK 000000003

/* The host file system device. */
typedef struct _device
{
    oe_device_t base;

    /* Must be FS_MAGIC. */
    uint32_t magic;

    /* True if this file system has been mounted. */
    bool is_mounted;

    /* The parameters that were passed to the mount() function. */
    struct
    {
        unsigned long flags;
        char source[OE_PATH_MAX];
        char target[OE_PATH_MAX];
    } mount;
} device_t;

/* Create by open(). */
typedef struct _file
{
    oe_fd_t base;

    /* Must be FILE_MAGIC. */
    uint32_t magic;

    /* The file descriptor obtained from the host or -1 for directory files. */
    oe_host_fd_t host_fd;

    /* The file descriptor for an open directory if non-null. */
    oe_fd_t* dir;
} file_t;

/* Created by opendir(), updated by readdir(), closed by closedir(). */
typedef struct _dir
{
    oe_fd_t base;

    /* Must be DIR_MAGIC. */
    uint32_t magic;

    /* The directory handle obtained from the host by opendir(). */
    uint64_t host_dir;

    /* The directory entry obtained from the host by readdir(). */
    struct oe_dirent entry;
} dir_t;

static oe_file_ops_t _get_file_ops(void);

static ssize_t _hostfs_read(oe_fd_t* desc, void* buf, size_t count);

static int _hostfs_close(oe_fd_t* desc);

static oe_fd_t* _hostfs_opendir(oe_device_t* device, const char* name);

static int _hostfs_closedir(oe_fd_t* desc);

static struct oe_dirent* _hostfs_readdir(oe_fd_t* desc);

/* Return true if the file system was mounted as read-only. */
OE_INLINE bool _is_read_only(const device_t* fs)
{
    return fs->mount.flags & OE_MS_RDONLY;
}

static device_t* _cast_device(const oe_device_t* device)
{
    device_t* ret = NULL;
    device_t* fs = (device_t*)device;

    if (fs == NULL || fs->magic != FS_MAGIC)
        goto done;

    ret = fs;

done:
    return ret;
}

static file_t* _cast_file(const oe_fd_t* desc)
{
    file_t* ret = NULL;
    file_t* file = (file_t*)desc;

    if (file == NULL || file->magic != FILE_MAGIC)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = file;

done:
    return ret;
}

static dir_t* _cast_dir(const oe_fd_t* desc)
{
    dir_t* ret = NULL;
    dir_t* dir = (dir_t*)desc;

    if (dir == NULL || dir->magic != DIR_MAGIC)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = dir;

done:
    return ret;
}

/* Expand an enclave path to a host path. */
static int _make_host_path(
    const device_t* fs,
    const char* enclave_path,
    char host_path[OE_PATH_MAX])
{
    const size_t n = OE_PATH_MAX;
    int ret = -1;

    if (oe_strcmp(fs->mount.source, "/") == 0)
    {
        if (oe_strlcpy(host_path, enclave_path, OE_PATH_MAX) >= n)
            OE_RAISE_ERRNO(OE_ENAMETOOLONG);
    }
    else
    {
        if (oe_strlcpy(host_path, fs->mount.source, OE_PATH_MAX) >= n)
            OE_RAISE_ERRNO(OE_ENAMETOOLONG);

        if (oe_strcmp(enclave_path, "/") != 0)
        {
            if (oe_strlcat(host_path, "/", OE_PATH_MAX) >= n)
                OE_RAISE_ERRNO(OE_ENAMETOOLONG);

            if (oe_strlcat(host_path, enclave_path, OE_PATH_MAX) >= n)
                OE_RAISE_ERRNO(OE_ENAMETOOLONG);
        }
    }

    ret = 0;

done:
    return ret;
}

/* Called by oe_mount(). */
static int _hostfs_mount(
    oe_device_t* device,
    const char* source,
    const char* target,
    const char* filesystemtype,
    unsigned long flags,
    const void* data)
{
    int ret = -1;
    device_t* fs = _cast_device(device);

    /* Fail if required parameters are null. */
    if (!fs || !source || !target)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Fail if this file system is already mounted. */
    if (fs->is_mounted)
        OE_RAISE_ERRNO(OE_EBUSY);

    /* Cross check the file system type. */
    if (oe_strcmp(filesystemtype, OE_DEVICE_NAME_HOST_FILE_SYSTEM) != 0)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* The data parameter is not supported for host file systems. */
    if (data)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Remember whether this is a read-only mount. */
    if ((flags & OE_MS_RDONLY))
        fs->mount.flags = flags;

    /* ---------------------------------------------------------------------
     * Only support absolute paths. Hostfs is treated as an external
     * filesystem. As such, it does not make sense to resolve relative paths
     * using the enclave's current working directory.
     * ---------------------------------------------------------------------
     */
    if (source && source[0] != '/')
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Save the source parameter (will be needed to form host paths). */
    oe_strlcpy(fs->mount.source, source, sizeof(fs->mount.source));

    /* Save the target parameter (checked by the umount2() function). */
    oe_strlcpy(fs->mount.target, target, sizeof(fs->mount.target));

    /* Set the flag indicating that this file system is mounted. */
    fs->is_mounted = true;

    ret = 0;

done:
    return ret;
}

/* Called by oe_umount2(). */
static int _hostfs_umount2(oe_device_t* device, const char* target, int flags)
{
    int ret = -1;
    device_t* fs = _cast_device(device);

    OE_UNUSED(flags);

    /* Fail if any required parameters are null. */
    if (!fs || !target)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Fail if this file system is not mounted. */
    if (!fs->is_mounted)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Cross check target parameter with the one passed to mount(). */
    if (oe_strcmp(target, fs->mount.target) != 0)
        OE_RAISE_ERRNO(OE_ENOENT);

    /* Clear the cached mount parameters. */
    oe_memset_s(&fs->mount, sizeof(fs->mount), 0, sizeof(fs->mount));

    /* Set the flag indicating that this file system is mounted. */
    fs->is_mounted = false;

    ret = 0;

done:
    return ret;
}

/* Called by oe_mount() to make a copy of this device. */
static int _hostfs_clone(oe_device_t* device, oe_device_t** new_device)
{
    int ret = -1;
    device_t* fs = _cast_device(device);
    device_t* new_fs = NULL;

    if (!fs || !new_device)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(new_fs = oe_calloc(1, sizeof(device_t))))
        OE_RAISE_ERRNO(OE_ENOMEM);

    *new_fs = *fs;
    *new_device = &new_fs->base;

    ret = 0;

done:
    return ret;
}

/* Called by oe_umount() to release this device. */
static int _hostfs_release(oe_device_t* device)
{
    int ret = -1;
    device_t* fs = _cast_device(device);

    if (!fs)
        OE_RAISE_ERRNO(OE_EINVAL);

    oe_free(fs);
    ret = 0;

done:
    return ret;
}

static oe_fd_t* _hostfs_open_file(
    oe_device_t* device,
    const char* pathname,
    int flags,
    oe_mode_t mode)
{
    oe_fd_t* ret = NULL;
    device_t* fs = _cast_device(device);
    file_t* file = NULL;
    char host_path[OE_PATH_MAX];
    oe_host_fd_t retval = -1;

    /* Fail if any required parameters are null. */
    if (!fs || !pathname)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Fail if attempting to write to a read-only file system. */
    if (_is_read_only(fs) && (flags & ACCESS_MODE_MASK) != OE_O_RDONLY)
        OE_RAISE_ERRNO(OE_EPERM);

    /* Create new file struct. */
    {
        if (!(file = oe_calloc(1, sizeof(file_t))))
            OE_RAISE_ERRNO(OE_ENOMEM);

        file->base.type = OE_FD_TYPE_FILE;
        file->magic = FILE_MAGIC;
        file->base.ops.file = _get_file_ops();
    }

    /* Ask the host to open the file. */
    {
        if (_make_host_path(fs, pathname, host_path) != 0)
            OE_RAISE_ERRNO_MSG(oe_errno, "pathname=%s", pathname);

        if (oe_syscall_open_ocall(&retval, host_path, flags, mode) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);

        if (retval < 0)
            goto done;

        file->host_fd = retval;
    }

    ret = &file->base;
    file = NULL;

done:

    if (file)
        oe_free(file);

    return ret;
}

static oe_fd_t* _hostfs_open_directory(
    oe_device_t* device,
    const char* pathname,
    int flags)
{
    oe_fd_t* ret = NULL;
    device_t* fs = _cast_device(device);
    file_t* file = NULL;
    oe_fd_t* dir = NULL;

    /* Check parameters */
    if (!fs || !pathname || !(flags & OE_O_DIRECTORY))
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Directories can only be opened for read access. */
    if ((flags & ACCESS_MODE_MASK) != OE_O_RDONLY)
        OE_RAISE_ERRNO(OE_EACCES);

    /* Attempt to open the directory. */
    if (!(dir = _hostfs_opendir(device, pathname)))
        OE_RAISE_ERRNO_MSG(oe_errno, "pathname=%s", pathname);

    /* Allocate and initialize the file struct. */
    {
        if (!(file = oe_calloc(1, sizeof(file_t))))
            OE_RAISE_ERRNO(OE_ENOMEM);

        file->base.type = OE_FD_TYPE_FILE;
        file->magic = FILE_MAGIC;
        file->base.ops.file = _get_file_ops();
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

static oe_fd_t* _hostfs_open(
    oe_device_t* fs,
    const char* pathname,
    int flags,
    oe_mode_t mode)
{
    if ((flags & OE_O_DIRECTORY))
    {
        /* Only existing directories can be opened, so mode is ignored. */
        return _hostfs_open_directory(fs, pathname, flags);
    }
    else
    {
        return _hostfs_open_file(fs, pathname, flags, mode);
    }
}

static int _hostfs_flock(oe_fd_t* desc, int operation)
{
    int ret = -1;
    file_t* file = _cast_file(desc);

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Call the host to perform the flock(). */
    if (oe_syscall_flock_ocall(&ret, file->host_fd, operation) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static int _hostfs_dup(oe_fd_t* desc, oe_fd_t** new_file_out)
{
    int ret = -1;
    file_t* file = _cast_file(desc);
    file_t* new_file = NULL;

    if (!new_file_out)
        OE_RAISE_ERRNO(OE_EINVAL);

    *new_file_out = NULL;

    /* Check parameters. */
    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Create and initialize the new file structure. */
    {
        if (!(new_file = oe_calloc(1, sizeof(file_t))))
            OE_RAISE_ERRNO(oe_errno);

        new_file->base.type = OE_FD_TYPE_FILE;
        new_file->base.ops.file = _get_file_ops();
        new_file->magic = FILE_MAGIC;
    }

    /* Call the host to perform the dup(). */
    {
        oe_host_fd_t retval = -1;

        if (oe_syscall_dup_ocall(&retval, file->host_fd) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);

        if (retval == -1)
            OE_RAISE_ERRNO(oe_errno);

        new_file->host_fd = retval;
    }

    *new_file_out = &new_file->base;
    new_file = NULL;
    ret = 0;

done:

    if (new_file)
        oe_free(new_file);

    return ret;
}

static ssize_t _hostfs_read(oe_fd_t* desc, void* buf, size_t count)
{
    ssize_t ret = -1;
    file_t* file = _cast_file(desc);

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Call the host to perform the read(). */
    if (oe_syscall_read_ocall(&ret, file->host_fd, buf, count) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

/* Called by oe_getdents64() to handle the getdents64 system call. */
static int _hostfs_getdents64(
    oe_fd_t* desc,
    struct oe_dirent* dirp,
    unsigned int count)
{
    int ret = -1;
    int bytes = 0;
    file_t* file = _cast_file(desc);
    unsigned int i;
    unsigned int n = count / sizeof(struct oe_dirent);

    if (!file || !file->dir || !dirp)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Read the entries one-by-one. */
    for (i = 0; i < n; i++)
    {
        struct oe_dirent* ent;

        oe_errno = 0;

        if (!(ent = _hostfs_readdir(file->dir)))
        {
            if (oe_errno)
            {
                OE_RAISE_ERRNO(oe_errno);
                goto done;
            }

            break;
        }

        *dirp = *ent;
        bytes += (int)sizeof(struct oe_dirent);
        dirp++;
    }

    ret = bytes;

done:
    return ret;
}

static ssize_t _hostfs_write(oe_fd_t* desc, const void* buf, size_t count)
{
    ssize_t ret = -1;
    file_t* file = _cast_file(desc);

    /* Check parameters. */
    if (!file || (count && !buf))
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Call the host. */
    if (oe_syscall_write_ocall(&ret, file->host_fd, buf, count) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _hostfs_readv(
    oe_fd_t* desc,
    const struct oe_iovec* iov,
    int iovcnt)
{
    ssize_t ret = -1;
    file_t* file = _cast_file(desc);
    void* buf = NULL;
    size_t buf_size = 0;

    if (!file || (!iov && iovcnt) || iovcnt < 0 || iovcnt > OE_IOV_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Flatten the IO vector into contiguous heap memory. */
    if (oe_iov_pack(iov, iovcnt, &buf, &buf_size) != 0)
        OE_RAISE_ERRNO(OE_ENOMEM);

    /* Call the host. */
    if (oe_syscall_readv_ocall(&ret, file->host_fd, buf, iovcnt, buf_size) !=
        OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    /* Synchronize data read with IO vector. */
    if (ret > 0)
    {
        if (oe_iov_sync(iov, iovcnt, buf, buf_size) != 0)
            OE_RAISE_ERRNO(OE_EINVAL);
    }

done:

    if (buf)
        oe_free(buf);

    return ret;
}

static ssize_t _hostfs_writev(
    oe_fd_t* desc,
    const struct oe_iovec* iov,
    int iovcnt)
{
    ssize_t ret = -1;
    file_t* file = _cast_file(desc);
    void* buf = NULL;
    size_t buf_size = 0;

    if (!file || !iov || iovcnt < 0 || iovcnt > OE_IOV_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Flatten the IO vector into contiguous heap memory. */
    if (oe_iov_pack(iov, iovcnt, &buf, &buf_size) != 0)
        OE_RAISE_ERRNO(OE_ENOMEM);

    /* Call the host. */
    if (oe_syscall_writev_ocall(&ret, file->host_fd, buf, iovcnt, buf_size) !=
        OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

done:

    if (buf)
        oe_free(buf);

    return ret;
}

static oe_off_t _hostfs_lseek_file(oe_fd_t* desc, oe_off_t offset, int whence)
{
    oe_off_t ret = -1;
    file_t* file = _cast_file(desc);

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_syscall_lseek_ocall(&ret, file->host_fd, offset, whence) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

/* Perform rewinddir on a dir struct. */
static int _hostfs_rewinddir(oe_fd_t* desc)
{
    int ret = -1;
    dir_t* dir = _cast_dir(desc);

    if (!dir)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_syscall_rewinddir_ocall(dir->host_dir) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = 0;

done:
    return ret;
}

/* Perform lseek on a dir struct (only rewind is permitted on a directory). */
static oe_off_t _hostfs_lseek_dir(oe_fd_t* desc, oe_off_t offset, int whence)
{
    oe_off_t ret = -1;
    file_t* file = _cast_file(desc);

    if (!file || !file->dir || offset != 0 || whence != OE_SEEK_SET)
        OE_RAISE_ERRNO(OE_EINVAL);

    if ((ret = _hostfs_rewinddir(file->dir)) == -1)
        OE_RAISE_ERRNO(oe_errno);

done:
    return ret;
}

static oe_off_t _hostfs_lseek(oe_fd_t* desc, oe_off_t offset, int whence)
{
    oe_off_t ret = -1;
    file_t* file = _cast_file(desc);

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (file->dir)
        ret = _hostfs_lseek_dir(desc, offset, whence);
    else
        ret = _hostfs_lseek_file(desc, offset, whence);

done:
    return ret;
}

static ssize_t _hostfs_pread(
    oe_fd_t* desc,
    void* buf,
    size_t count,
    oe_off_t offset)
{
    ssize_t ret = -1;
    file_t* file = _cast_file(desc);

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_syscall_pread_ocall(&ret, file->host_fd, buf, count, offset) !=
        OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _hostfs_pwrite(
    oe_fd_t* desc,
    const void* buf,
    size_t count,
    oe_off_t offset)
{
    ssize_t ret = -1;
    file_t* file = _cast_file(desc);

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_syscall_pwrite_ocall(&ret, file->host_fd, buf, count, offset) !=
        OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static int _hostfs_close_file(oe_fd_t* desc)
{
    int ret = -1;
    int retval = -1;
    file_t* file = _cast_file(desc);

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_syscall_close_ocall(&retval, file->host_fd) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (retval == -1)
        OE_RAISE_ERRNO(oe_errno);

    oe_free(file);

    ret = retval;

done:
    return ret;
}

/* Close a directory file. */
static int _hostfs_close_directory(oe_fd_t* desc)
{
    int ret = -1;
    file_t* file = _cast_file(desc);

    /* Check parameters. */
    if (!file || !file->dir)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Release the directory object. */
    if (_hostfs_closedir(file->dir) != 0)
        OE_RAISE_ERRNO(oe_errno);

    /* Release the file object. */
    oe_free(file);

    ret = 0;

done:
    return ret;
}

static int _hostfs_close(oe_fd_t* desc)
{
    int ret = -1;
    file_t* file = _cast_file(desc);

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (file->dir)
        ret = _hostfs_close_directory(desc);
    else
        ret = _hostfs_close_file(desc);

done:
    return ret;
}

static int _hostfs_ioctl(oe_fd_t* desc, unsigned long request, uint64_t arg)
{
    int ret = -1;
    file_t* file = _cast_file(desc);
    uint64_t argsize = 0;
    void* argout = NULL;

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    /*
     * MUSL uses the TIOCGWINSZ ioctl request to determine whether the file
     * descriptor refers to a terminal device. This request cannot be handled
     * by Windows hosts, so the error is handled on the enclave side. This is
     * the correct behavior since host files are not terminal devices.
     */
    switch (request)
    {
        default:
            OE_RAISE_ERRNO(OE_ENOTTY);
    }

    /* Call the host to perform the ioctl() operation. */
    if (oe_syscall_ioctl_ocall(
            &ret, file->host_fd, request, arg, argsize, argout) != OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

done:
    return ret;
}

static int _hostfs_fcntl(oe_fd_t* desc, int cmd, uint64_t arg)
{
    int ret = -1;
    file_t* file = _cast_file(desc);
    void* argout = NULL;
    uint64_t argsize = 0;

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    switch (cmd)
    {
        case OE_F_GETFD:
        case OE_F_SETFD:
        case OE_F_GETFL:
        case OE_F_SETFL:
            break;

        case OE_F_GETLK64:
        case OE_F_OFD_GETLK:
            argsize = sizeof(struct oe_flock);
            argout = (void*)arg;
            break;

        case OE_F_SETLKW64:
        case OE_F_SETLK64:
        {
            void* srcp = (void*)arg;
            argsize = sizeof(struct oe_flock64);
            argout = (void*)arg;
            memcpy(argout, srcp, argsize);
            break;
        }

        case OE_F_OFD_SETLK:
        case OE_F_OFD_SETLKW:
        {
            void* srcp = (void*)arg;
            argsize = sizeof(struct oe_flock64);
            argout = (void*)arg;
            memcpy(argout, srcp, argsize);
            break;
        }

        // for sockets
        default:
        case OE_F_DUPFD: // Should be handled in posix layer
        case OE_F_SETOWN:
        case OE_F_GETOWN:
        case OE_F_SETSIG:
        case OE_F_GETSIG:
        case OE_F_SETOWN_EX:
        case OE_F_GETOWN_EX:
        case OE_F_GETOWNER_UIDS:
            OE_RAISE_ERRNO(OE_EINVAL);
    }

    if (oe_syscall_fcntl_ocall(
            &ret, file->host_fd, cmd, arg, argsize, argout) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

/* Open a directory file. */
static oe_fd_t* _hostfs_opendir(oe_device_t* device, const char* name)
{
    oe_fd_t* ret = NULL;
    device_t* fs = _cast_device(device);
    dir_t* dir = NULL;
    char host_name[OE_PATH_MAX];
    uint64_t retval = 0;

    if (!fs || !name)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (_make_host_path(fs, name, host_name) != 0)
        OE_RAISE_ERRNO_MSG(oe_errno, "name=%s", name);

    if (!(dir = oe_calloc(1, sizeof(dir_t))))
        OE_RAISE_ERRNO(OE_ENOMEM);

    if (oe_syscall_opendir_ocall(&retval, host_name) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!retval)
        OE_RAISE_ERRNO(oe_errno);

    dir->base.type = OE_FD_TYPE_FILE;
    dir->magic = DIR_MAGIC;
    dir->base.ops.file = _get_file_ops();
    dir->host_dir = retval;

    ret = &dir->base;
    dir = NULL;

done:

    if (dir)
        oe_free(dir);

    return ret;
}

/* Get the next directory entry from the host. */
static struct oe_dirent* _hostfs_readdir(oe_fd_t* desc)
{
    struct oe_dirent* ret = NULL;
    dir_t* dir = _cast_dir(desc);
    int retval = -1;

    if (!dir)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Call the host to get the next directory entry. */
    if (oe_syscall_readdir_ocall(&retval, dir->host_dir, &dir->entry) != OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    /* Handle any error. */
    if (retval == -1)
        OE_RAISE_ERRNO(oe_errno);

    /* If end of file, then return NULL. */
    if (retval == 1)
        goto done;

    /* Check for an unexpected return value (indicates a coding error). */
    if (retval != 0)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = &dir->entry;

done:

    return ret;
}

/* Close the directory file. */
static int _hostfs_closedir(oe_fd_t* desc)
{
    int ret = -1;
    dir_t* dir = _cast_dir(desc);
    int retval = -1;

    if (!dir)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_syscall_closedir_ocall(&retval, dir->host_dir) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    oe_free(dir);

    ret = retval;

done:

    return ret;
}

static int _hostfs_stat(
    oe_device_t* device,
    const char* pathname,
    struct oe_stat_t* buf)
{
    int ret = -1;
    device_t* fs = _cast_device(device);
    char host_path[OE_PATH_MAX];
    int retval = -1;

    if (buf)
        oe_memset_s(buf, sizeof(*buf), 0, sizeof(*buf));

    if (!fs || !pathname || !buf)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (_make_host_path(fs, pathname, host_path) != 0)
        OE_RAISE_ERRNO(oe_errno);

    if (oe_syscall_stat_ocall(&retval, host_path, buf) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = retval;

done:

    return ret;
}

static int _hostfs_access(oe_device_t* device, const char* pathname, int mode)
{
    int ret = -1;
    device_t* fs = _cast_device(device);
    char host_path[OE_PATH_MAX];
    const uint32_t MASK = (OE_R_OK | OE_W_OK | OE_X_OK);
    int retval = -1;

    if (!fs || !pathname || ((uint32_t)mode & ~MASK))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (_make_host_path(fs, pathname, host_path) != 0)
        OE_RAISE_ERRNO(oe_errno);

    if (oe_syscall_access_ocall(&retval, host_path, mode) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = retval;

done:

    return ret;
}

static int _hostfs_link(
    oe_device_t* device,
    const char* oldpath,
    const char* newpath)
{
    int ret = -1;
    device_t* fs = _cast_device(device);
    char host_oldpath[OE_PATH_MAX];
    char host_newpath[OE_PATH_MAX];
    int retval = -1;

    if (!fs || !oldpath || !newpath)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Fail if attempting to write to a read-only file system. */
    if (_is_read_only(fs))
        OE_RAISE_ERRNO(OE_EPERM);

    if (_make_host_path(fs, oldpath, host_oldpath) != 0)
        OE_RAISE_ERRNO(oe_errno);

    if (_make_host_path(fs, newpath, host_newpath) != 0)
        OE_RAISE_ERRNO(oe_errno);

    if (oe_syscall_link_ocall(&retval, host_oldpath, host_newpath) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = retval;

done:

    return ret;
}

static int _hostfs_unlink(oe_device_t* device, const char* pathname)
{
    int ret = -1;
    device_t* fs = _cast_device(device);
    char host_path[OE_PATH_MAX];
    int retval = -1;

    if (!fs)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Fail if attempting to write to a read-only file system. */
    if (_is_read_only(fs))
        OE_RAISE_ERRNO(OE_EPERM);

    if (_make_host_path(fs, pathname, host_path) != 0)
        OE_RAISE_ERRNO(oe_errno);

    if (oe_syscall_unlink_ocall(&retval, host_path) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = retval;

done:

    return ret;
}

static int _hostfs_rename(
    oe_device_t* device,
    const char* oldpath,
    const char* newpath)
{
    int ret = -1;
    device_t* fs = _cast_device(device);
    char host_oldpath[OE_PATH_MAX];
    char host_newpath[OE_PATH_MAX];
    int retval = -1;

    if (!fs || !oldpath || !newpath)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (_is_read_only(fs))
        OE_RAISE_ERRNO(OE_EPERM);

    if (_make_host_path(fs, oldpath, host_oldpath) != 0)
        OE_RAISE_ERRNO(oe_errno);

    if (_make_host_path(fs, newpath, host_newpath) != 0)
        OE_RAISE_ERRNO(oe_errno);

    if (oe_syscall_rename_ocall(&retval, host_oldpath, host_newpath) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = retval;

done:

    return ret;
}

static int _hostfs_truncate(
    oe_device_t* device,
    const char* path,
    oe_off_t length)
{
    int ret = -1;
    device_t* fs = _cast_device(device);
    char host_path[OE_PATH_MAX];
    int retval = -1;

    if (!fs)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (_is_read_only(fs))
        OE_RAISE_ERRNO(OE_EPERM);

    if (_make_host_path(fs, path, host_path) != 0)
        OE_RAISE_ERRNO(oe_errno);

    if (oe_syscall_truncate_ocall(&retval, host_path, length) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = retval;

done:

    return ret;
}

static int _hostfs_mkdir(
    oe_device_t* device,
    const char* pathname,
    oe_mode_t mode)
{
    int ret = -1;
    device_t* fs = _cast_device(device);
    char host_path[OE_PATH_MAX];
    int retval = -1;

    if (!fs)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Fail if attempting to write to a read-only file system. */
    if (_is_read_only(fs))
        OE_RAISE_ERRNO(OE_EPERM);

    if (_make_host_path(fs, pathname, host_path) != 0)
        OE_RAISE_ERRNO(oe_errno);

    if (oe_syscall_mkdir_ocall(&retval, host_path, mode) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = retval;

done:

    return ret;
}

static int _hostfs_rmdir(oe_device_t* device, const char* pathname)
{
    int ret = -1;
    device_t* fs = _cast_device(device);
    char host_path[OE_PATH_MAX];
    int retval = -1;

    if (!fs)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Fail if attempting to write to a read-only file system. */
    if (_is_read_only(fs))
        OE_RAISE_ERRNO(OE_EPERM);

    if (_make_host_path(fs, pathname, host_path) != 0)
        OE_RAISE_ERRNO(oe_errno);

    if (oe_syscall_rmdir_ocall(&retval, host_path) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = retval;

done:

    return ret;
}

static oe_host_fd_t _hostfs_get_host_fd(oe_fd_t* desc)
{
    file_t* file = _cast_file(desc);

    return file ? file->host_fd : -1;
}

// clang-format off
static oe_file_ops_t _file_ops =
{
    .fd.read = _hostfs_read,
    .fd.write = _hostfs_write,
    .fd.readv = _hostfs_readv,
    .fd.writev = _hostfs_writev,
    .fd.flock = _hostfs_flock,
    .fd.dup = _hostfs_dup,
    .fd.ioctl = _hostfs_ioctl,
    .fd.fcntl = _hostfs_fcntl,
    .fd.close = _hostfs_close,
    .fd.get_host_fd = _hostfs_get_host_fd,
    .lseek = _hostfs_lseek,
    .pread = _hostfs_pread,
    .pwrite = _hostfs_pwrite,
    .getdents64 = _hostfs_getdents64,
};
// clang-format on

static oe_file_ops_t _get_file_ops(void)
{
    return _file_ops;
};

// clang-format off
static device_t _hostfs =
{
    .base.type = OE_DEVICE_TYPE_FILE_SYSTEM,
    .base.name = OE_DEVICE_NAME_HOST_FILE_SYSTEM,
    .base.ops.fs =
    {
        .base.release = _hostfs_release,
        .clone = _hostfs_clone,
        .mount = _hostfs_mount,
        .umount2 = _hostfs_umount2,
        .open = _hostfs_open,
        .stat = _hostfs_stat,
        .access = _hostfs_access,
        .link = _hostfs_link,
        .unlink = _hostfs_unlink,
        .rename = _hostfs_rename,
        .truncate = _hostfs_truncate,
        .mkdir = _hostfs_mkdir,
        .rmdir = _hostfs_rmdir,
    },
    .magic = FS_MAGIC,
    .mount =
    {
         .source = {'/'},
    }
};
// clang-format on

oe_device_t* oe_get_hostfs_device(void)
{
    return &_hostfs.base;
}

oe_result_t oe_load_module_host_file_system(void)
{
    oe_result_t result = OE_UNEXPECTED;
    static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
    static bool _loaded = false;

    oe_spin_lock(&_lock);

    if (!_loaded)
    {
        if (oe_device_table_set(OE_DEVID_HOST_FILE_SYSTEM, &_hostfs.base) != 0)
        {
            /* Do not propagate errno to caller. */
            oe_errno = 0;
            OE_RAISE(OE_FAILURE);
        }

        _loaded = true;
    }

    result = OE_OK;

done:
    oe_spin_unlock(&_lock);

    return result;
}
