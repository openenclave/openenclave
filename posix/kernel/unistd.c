// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/pthread.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/sys/stat.h>
#include <openenclave/corelibc/sys/utsname.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/time.h>
#include <openenclave/internal/trace.h>
#include "device.h"
#include "mount.h"
#include "posix_t.h"

int oe_gethostname(char* name, size_t len)
{
    int ret = -1;
    struct oe_utsname uts;

    if ((ret = oe_uname(&uts)) != 0)
    {
        OE_TRACE_ERROR("name=%s len=%ld ret=%d", name, len, ret);
        ret = -1;
        goto done;
    }

    oe_strlcpy(name, uts.nodename, len);
    ret = 0;

done:
    return ret;
}

int oe_getdomainname(char* name, size_t len)
{
    int ret = -1;
    struct oe_utsname uts;

    if ((ret = oe_uname(&uts)) != 0)
    {
        OE_TRACE_ERROR("name=%s len=%ld ret=%d", name, len, ret);
        ret = -1;
        goto done;
    }

#ifdef _GNU_SOURCE
    oe_strlcpy(name, uts.domainname, len);
#else
    oe_strlcpy(name, uts.__domainname, len);
#endif
    ret = 0;

done:
    return ret;
}

static char _cwd[OE_PATH_MAX] = "/";
static oe_pthread_spinlock_t _lock;

char* oe_getcwd(char* buf, size_t size)
{
    char* ret = NULL;
    char* p = NULL;
    size_t n;
    bool locked = false;

    if (buf && size == 0)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    if (!buf)
    {
        n = OE_PATH_MAX;
        p = oe_malloc(n);

        if (!p)
        {
            oe_errno = OE_ENOMEM;
            OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
            goto done;
        }
    }
    else
    {
        n = size;
        p = buf;
    }

    oe_pthread_spin_lock(&_lock);
    locked = true;

    if (oe_strlcpy(p, _cwd, n) >= n)
    {
        oe_errno = OE_ERANGE;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    oe_pthread_spin_unlock(&_lock);
    locked = false;

    ret = p;
    p = NULL;

done:

    if (locked)
        oe_pthread_spin_unlock(&_lock);

    if (p && p != buf)
        oe_free(p);

    return ret;
}

int oe_chdir(const char* path)
{
    int ret = -1;
    char real_path[OE_PATH_MAX];
    struct oe_stat st;
    bool locked = false;

    /* Resolve to an absolute canonical path. */
    if (!oe_realpath(path, real_path))
        return -1;

    /* Fail if unable to stat the path. */
    if (oe_stat(real_path, &st) != 0)
    {
        // oe_errno set by oe_stat().
        return -1;
    }

    /* Fail if path not a directory. */
    if (!OE_S_ISDIR(st.st_mode))
    {
        oe_errno = OE_ENOTDIR;
        return -1;
    }

    /* Set the _cwd global. */
    oe_pthread_spin_lock(&_lock);
    locked = true;

    if (oe_strlcpy(_cwd, real_path, OE_PATH_MAX) >= OE_PATH_MAX)
    {
        oe_errno = OE_ENAMETOOLONG;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    oe_pthread_spin_unlock(&_lock);
    locked = false;

    ret = 0;

done:

    if (locked)
        oe_pthread_spin_unlock(&_lock);

    return ret;
}

unsigned int oe_sleep(unsigned int seconds)
{
    const uint64_t ONE_SECOND = 1000;
    const uint64_t msec = seconds * ONE_SECOND;

    return (oe_sleep_msec(msec) == 0) ? 0 : seconds;
}

oe_pid_t oe_getpid(void)
{
    oe_pid_t ret = 0;
    oe_posix_getpid(&ret);
    return ret;
}

oe_pid_t oe_getppid(void)
{
    oe_pid_t ret = 0;
    oe_posix_getppid(&ret);
    return ret;
}

oe_pid_t oe_getpgrp(void)
{
    oe_pid_t ret = 0;
    oe_posix_getpgrp(&ret);
    return ret;
}

oe_uid_t oe_getuid(void)
{
    oe_uid_t ret = 0;
    oe_posix_getuid(&ret);
    return ret;
}

oe_uid_t oe_geteuid(void)
{
    oe_uid_t ret = 0;
    oe_posix_geteuid(&ret);
    return ret;
}

oe_gid_t oe_getgid(void)
{
    oe_gid_t ret = 0;
    oe_posix_getgid(&ret);
    return ret;
}

oe_gid_t oe_getegid(void)
{
    oe_gid_t ret = 0;
    oe_posix_getegid(&ret);
    return ret;
}

oe_pid_t oe_getpgid(oe_pid_t pid)
{
    oe_pid_t ret = -1;
    oe_pid_t retval = -1;

    if (oe_posix_getpgid(&retval, pid) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    if (retval == -1)
        goto done;

    ret = retval;

done:
    return ret;
}

int oe_getgroups(int size, oe_gid_t list[])
{
    int ret = -1;
    int retval = -1;

    if (oe_posix_getgroups(&retval, (size_t)size, list) != OE_OK)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    if (retval == -1)
    {
        goto done;
    }

    ret = retval;

done:
    return ret;
}

ssize_t oe_read(int fd, void* buf, size_t count)
{
    ssize_t ret = -1;
    oe_device_t* device;
    ssize_t n;

    if (!(device = oe_get_fd_device(fd, OE_DEVICE_TYPE_NONE)))
    {
        OE_TRACE_ERROR("no device found fd=%d", fd);
        goto done;
    }

    if (device->ops.base->read == NULL)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    // The action routine sets errno
    if ((n = (*device->ops.base->read)(device, buf, count)) < 0)
    {
        OE_TRACE_ERROR("fd = %d n = %zd", fd, n);
        goto done;
    }

    ret = n;

done:
    return ret;
}

ssize_t oe_write(int fd, const void* buf, size_t count)
{
    ssize_t ret = -1;
    oe_device_t* device;

    OE_TRACE_VERBOSE("fd=%d", fd);

    if (!(device = oe_get_fd_device(fd, OE_DEVICE_TYPE_NONE)))
    {
        oe_errno = OE_EBADF;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    if (device->ops.base->write == NULL)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    // The action routine sets errno
    ret = (*device->ops.base->write)(device, buf, count);

done:
    return ret;
}

int oe_close(int fd)
{
    int ret = -1;
    int retval = -1;
    oe_device_t* device;

    if (!(device = oe_get_fd_device(fd, OE_DEVICE_TYPE_NONE)))
    {
        OE_TRACE_ERROR("no device found for fd=%d", fd);
        goto done;
    }

    if (device->ops.base->close == NULL)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d ", oe_errno);
        goto done;
    }

    if ((retval = (*device->ops.base->close)(device)) != 0)
    {
        OE_TRACE_ERROR("fd =%d retval=%d", fd, retval);
        goto done;
    }

    oe_release_fd(fd);

    ret = 0;

done:
    return ret;
}

int oe_dup(int oldfd)
{
    oe_device_t* old_dev;
    oe_device_t* new_dev = NULL;
    int newfd = -1;
    int retval = -1;

    if (!(old_dev = oe_get_fd_device(oldfd, OE_DEVICE_TYPE_NONE)))
    {
        oe_errno = OE_EBADF;
        OE_TRACE_ERROR("oldfd=%d oe_errno=%d", oldfd, oe_errno);
        goto done;
    }

    if ((retval = (*old_dev->ops.base->dup)(old_dev, &new_dev)) < 0)
    {
        oe_errno = OE_EBADF;
        OE_TRACE_ERROR(
            "oldfd=%d oe_errno=%d retval=%d", oldfd, oe_errno, retval);
        newfd = -1;
        goto done;
    }

    if (!(newfd = oe_assign_fd_device(new_dev)))
    {
        // ATTN: release new_dev here.
    }

done:

    return newfd;
}

int oe_dup2(int oldfd, int newfd)
{
    oe_device_t* old_dev;
    oe_device_t* new_dev;
    oe_device_t* dev = NULL;
    int retval = -1;

    if (!(old_dev = oe_get_fd_device(oldfd, OE_DEVICE_TYPE_NONE)))
    {
        oe_errno = OE_EBADF;
        OE_TRACE_ERROR("oldfd=%d oe_errno=%d", oldfd, oe_errno);
        goto done;
    }

    if (!(new_dev = oe_get_fd_device(newfd, OE_DEVICE_TYPE_NONE)))
    {
        (*new_dev->ops.base->close)(new_dev);
    }

    if ((retval = (*old_dev->ops.base->dup)(old_dev, &dev)) < 0)
    {
        oe_errno = OE_EBADF;
        newfd = -1;
        goto done;
    }

    // ATTN: release dev if this fails. */
    if (oe_set_fd_device(newfd, dev))
    {
        oe_errno = OE_EBADF;
        OE_TRACE_ERROR("newfd=%d dev=%p oe_errno=%d", newfd, dev, oe_errno);
        (*dev->ops.base->close)(dev);
        newfd = -1;
        goto done;
    }

done:

    return newfd;
}

int oe_rmdir(const char* pathname)
{
    int ret = -1;
    oe_device_t* fs = NULL;
    char filepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(pathname, filepath)))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (fs->ops.fs->rmdir == NULL)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    ret = (*fs->ops.fs->rmdir)(fs, filepath);

done:
    return ret;
}

int oe_rmdir_d(uint64_t devid, const char* pathname)
{
    int ret = -1;

    if (devid == OE_DEVID_NONE)
    {
        ret = oe_rmdir(pathname);
    }
    else
    {
        oe_device_t* dev;

        if (!(dev = oe_get_fs_device(devid)))
        {
            oe_errno = OE_EINVAL;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        if ((ret = dev->ops.fs->rmdir(dev, pathname)) != 0)
        {
            OE_TRACE_ERROR(
                "devid=%lu pathname=%s ret=%d", devid, pathname, ret);
        }
    }

done:
    return ret;
}

int oe_link(const char* oldpath, const char* newpath)
{
    int ret = -1;
    oe_device_t* fs = NULL;
    oe_device_t* newfs = NULL;
    char filepath[OE_PATH_MAX] = {0};
    char newfilepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(oldpath, filepath)))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (!(newfs = oe_mount_resolve(newpath, newfilepath)))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (fs != newfs)
    {
        oe_errno = OE_EXDEV;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (fs->ops.fs->link == NULL)
    {
        oe_errno = OE_EPERM;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    ret = (*fs->ops.fs->link)(fs, filepath, newfilepath);

done:
    return ret;
}

int oe_link_d(uint64_t devid, const char* oldpath, const char* newpath)
{
    int ret = -1;

    if (devid == OE_DEVID_NONE)
    {
        ret = oe_link(oldpath, newpath);
    }
    else
    {
        oe_device_t* dev;

        if (!(dev = oe_get_fs_device(devid)))
        {
            oe_errno = OE_EINVAL;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        ret = dev->ops.fs->link(dev, oldpath, newpath);
        if (ret != 0)
        {
            OE_TRACE_ERROR(
                "devid=%lu oldpath=%s newpath=%s ret=%d",
                devid,
                oldpath,
                newpath,
                ret);
        }
    }

done:
    return ret;
}

int oe_unlink(const char* pathname)
{
    int ret = -1;
    oe_device_t* fs = NULL;
    char filepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(pathname, filepath)))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (fs->ops.fs->unlink == NULL)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    ret = (*fs->ops.fs->unlink)(fs, filepath);

done:
    return ret;
}

int oe_unlink_d(uint64_t devid, const char* pathname)
{
    int ret = -1;

    if (devid == OE_DEVID_NONE)
    {
        ret = oe_unlink(pathname);
    }
    else
    {
        oe_device_t* dev;

        if (!(dev = oe_get_fs_device(devid)))
        {
            oe_errno = OE_EINVAL;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        if ((ret = dev->ops.fs->unlink(dev, pathname)) != 0)
        {
            OE_TRACE_ERROR(
                "devid=%lu pathname=%s ret=%d", devid, pathname, ret);
        }
    }

done:
    return ret;
}

int oe_truncate(const char* pathname, oe_off_t length)
{
    int ret = -1;
    oe_device_t* fs = NULL;
    char filepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(pathname, filepath)))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (fs->ops.fs->truncate == NULL)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    ret = (*fs->ops.fs->truncate)(fs, filepath, length);

done:
    return ret;
}

int oe_truncate_d(uint64_t devid, const char* path, oe_off_t length)
{
    int ret = -1;

    if (devid == OE_DEVID_NONE)
    {
        ret = oe_truncate(path, length);
    }
    else
    {
        oe_device_t* dev;

        if (!(dev = oe_get_fs_device(devid)))
        {
            oe_errno = OE_EINVAL;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        if ((ret = dev->ops.fs->truncate(dev, path, length)) != 0)
        {
            OE_TRACE_ERROR("devid=%lu path=%s ret=%d", devid, path, ret);
        }
    }

done:
    return ret;
}

oe_off_t oe_lseek(int fd, oe_off_t offset, int whence)
{
    oe_off_t ret = -1;
    oe_device_t* file;

    if (!(file = oe_get_fd_device(fd, OE_DEVICE_TYPE_FILE)))
    {
        oe_errno = OE_EBADF;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (file->ops.fs->lseek == NULL)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    ret = (*file->ops.fs->lseek)(file, offset, whence);

done:
    return ret;
}

ssize_t oe_readv(int fd, const struct oe_iovec* iov, int iovcnt)
{
    ssize_t ret = -1;
    ssize_t nread = 0;

    if (fd < 0 || !iov)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    for (int i = 0; i < iovcnt; i++)
    {
        const struct oe_iovec* p = &iov[i];
        ssize_t n;

        n = oe_read(fd, p->iov_base, p->iov_len);
        if (n < 0)
        {
            OE_TRACE_ERROR("n = %ld", n);
            goto done;
        }

        nread += n;

        if ((size_t)n < p->iov_len)
            break;
    }

    ret = nread;

done:
    return ret;
}

ssize_t oe_writev(int fd, const struct oe_iovec* iov, int iovcnt)
{
    ssize_t ret = -1;
    ssize_t nwritten = 0;

    if (fd < 0 || !iov)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    for (int i = 0; i < iovcnt; i++)
    {
        const struct oe_iovec* p = &iov[i];
        ssize_t n;

        n = oe_write(fd, p->iov_base, p->iov_len);

        if ((size_t)n != p->iov_len)
        {
            oe_errno = OE_EIO;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        nwritten += n;
    }

    ret = nwritten;

done:
    return ret;
}

int oe_access(const char* pathname, int mode)
{
    int ret = -1;
    oe_device_t* fs = NULL;
    char suffix[OE_PATH_MAX];

    if (!(fs = oe_mount_resolve(pathname, suffix)))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (fs->ops.fs->access == NULL)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    ret = (*fs->ops.fs->access)(fs, suffix, mode);

done:
    return ret;
}

int oe_access_d(uint64_t devid, const char* pathname, int mode)
{
    int ret = -1;

    if (devid == OE_DEVID_NONE)
    {
        ret = oe_access(pathname, mode);
    }
    else
    {
        oe_device_t* dev;
        struct oe_stat buf;

        if (!(dev = oe_get_fs_device(devid)))
        {
            oe_errno = OE_EINVAL;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        if (!pathname)
        {
            oe_errno = OE_EINVAL;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        if (oe_stat(pathname, &buf) != 0)
        {
            oe_errno = OE_ENOENT;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        ret = 0;
    }

done:
    return ret;
}
