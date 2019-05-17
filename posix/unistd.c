// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/sys/stat.h>
#include <openenclave/corelibc/sys/utsname.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/posix/device.h>
#include <openenclave/internal/posix/fdtable.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/time.h>
#include <openenclave/internal/trace.h>
#include "mount.h"
#include "posix_t.h"

int oe_gethostname(char* name, size_t len)
{
    int ret = -1;
    struct oe_utsname uts;

    if ((ret = oe_uname(&uts)) != 0)
        OE_RAISE_ERRNO(oe_errno);

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
        OE_RAISE_ERRNO(oe_errno);

    oe_strlcpy(name, uts.domainname, len);

    ret = 0;

done:
    return ret;
}

static char _cwd[OE_PATH_MAX] = "/";
static oe_spinlock_t _cwd_lock;

char* oe_getcwd(char* buf, size_t size)
{
    char* ret = NULL;
    char* p = NULL;
    size_t n;
    bool locked = false;

    if (buf && size == 0)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!buf)
    {
        n = OE_PATH_MAX;
        p = oe_malloc(n);

        if (!p)
            OE_RAISE_ERRNO(OE_ENOMEM);
    }
    else
    {
        n = size;
        p = buf;
    }

    oe_spin_lock(&_cwd_lock);
    locked = true;

    if (oe_strlcpy(p, _cwd, n) >= n)
        OE_RAISE_ERRNO(OE_ERANGE);

    oe_spin_unlock(&_cwd_lock);
    locked = false;

    ret = p;
    p = NULL;

done:

    if (locked)
        oe_spin_unlock(&_cwd_lock);

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
    oe_spin_lock(&_cwd_lock);
    locked = true;

    if (oe_strlcpy(_cwd, real_path, OE_PATH_MAX) >= OE_PATH_MAX)
        OE_RAISE_ERRNO(OE_ENAMETOOLONG);

    ret = 0;

done:

    if (locked)
        oe_spin_unlock(&_cwd_lock);

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
    oe_fd_t* desc;

    if (!(desc = oe_fdtable_get(fd, OE_FD_TYPE_ANY)))
        OE_RAISE_ERRNO(OE_EBADF);

    ret = desc->ops.fd.read(desc, buf, count);

done:
    return ret;
}

ssize_t oe_write(int fd, const void* buf, size_t count)
{
    ssize_t ret = -1;
    oe_fd_t* desc;

    if (!(desc = oe_fdtable_get(fd, OE_FD_TYPE_ANY)))
        OE_RAISE_ERRNO(OE_EBADF);

    ret = desc->ops.fd.write(desc, buf, count);

done:
    return ret;
}

int oe_close(int fd)
{
    int ret = -1;
    oe_fd_t* desc;

    if (!(desc = oe_fdtable_get(fd, OE_FD_TYPE_ANY)))
        OE_RAISE_ERRNO(OE_EBADF);

    if ((ret = desc->ops.fd.close(desc)) == 0)
        oe_fdtable_release(fd);

done:
    return ret;
}

int oe_dup(int oldfd)
{
    int ret = -1;
    oe_fd_t* old_desc;
    oe_fd_t* new_desc = NULL;
    int newfd;

    if (!(old_desc = oe_fdtable_get(oldfd, OE_FD_TYPE_ANY)))
        OE_RAISE_ERRNO(OE_EBADF);

    if (old_desc->ops.fd.dup(old_desc, &new_desc) == -1)
        OE_RAISE_ERRNO(oe_errno);

    if ((newfd = oe_fdtable_assign(new_desc)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    ret = newfd;
    new_desc = NULL;

done:

    if (new_desc)
        new_desc->ops.fd.close(new_desc);

    return ret;
}

int oe_dup2(int oldfd, int newfd)
{
    oe_fd_t* old_desc;
    oe_fd_t* new_desc = NULL;
    int retval = -1;

    if (oldfd == newfd)
        return newfd;

    if (!(old_desc = oe_fdtable_get(oldfd, OE_FD_TYPE_ANY)))
        OE_RAISE_ERRNO(OE_EBADF);

    if ((retval = old_desc->ops.fd.dup(old_desc, &new_desc)) < 0)
        OE_RAISE_ERRNO(oe_errno);

    if (oe_fdtable_reassign(newfd, new_desc) == -1)
        OE_RAISE_ERRNO(OE_EINVAL);

    new_desc = NULL;

done:

    if (new_desc)
        new_desc->ops.fd.close(new_desc);

    return newfd;
}

int oe_rmdir(const char* pathname)
{
    int ret = -1;
    oe_device_t* fs = NULL;
    char filepath[OE_PATH_MAX] = {0};

    if (!(fs = oe_mount_resolve(pathname, filepath)))
        OE_RAISE_ERRNO(oe_errno);

    ret = fs->ops.fs.rmdir(fs, filepath);

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

        if (!(dev = oe_get_device(devid, OE_DEVICE_TYPE_FILE_SYSTEM)))
            OE_RAISE_ERRNO(OE_EINVAL);

        ret = dev->ops.fs.rmdir(dev, pathname);
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
        OE_RAISE_ERRNO(oe_errno);

    if (!(newfs = oe_mount_resolve(newpath, newfilepath)))
        OE_RAISE_ERRNO(oe_errno);

    if (fs != newfs)
        OE_RAISE_ERRNO(OE_EXDEV);

    ret = fs->ops.fs.link(fs, filepath, newfilepath);

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

        if (!(dev = oe_get_device(devid, OE_DEVICE_TYPE_FILE_SYSTEM)))
            OE_RAISE_ERRNO(OE_EINVAL);

        ret = dev->ops.fs.link(dev, oldpath, newpath);
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
        OE_RAISE_ERRNO(oe_errno);

    ret = fs->ops.fs.unlink(fs, filepath);

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

        if (!(dev = oe_get_device(devid, OE_DEVICE_TYPE_FILE_SYSTEM)))
            OE_RAISE_ERRNO(OE_EINVAL);

        ret = dev->ops.fs.unlink(dev, pathname);
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
        OE_RAISE_ERRNO(oe_errno);

    ret = fs->ops.fs.truncate(fs, filepath, length);

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

        if (!(dev = oe_get_device(devid, OE_DEVICE_TYPE_FILE_SYSTEM)))
            OE_RAISE_ERRNO(OE_EINVAL);

        ret = dev->ops.fs.truncate(dev, path, length);
    }

done:
    return ret;
}

oe_off_t oe_lseek(int fd, oe_off_t offset, int whence)
{
    oe_off_t ret = -1;
    oe_fd_t* file;

    if (!(file = oe_fdtable_get(fd, OE_FD_TYPE_FILE)))
        OE_RAISE_ERRNO(OE_EBADF);

    ret = file->ops.file.lseek(file, offset, whence);

done:
    return ret;
}

ssize_t oe_readv(int fd, const struct oe_iovec* iov, int iovcnt)
{
    ssize_t ret = -1;
    ssize_t nread = 0;

    if (fd < 0 || !iov)
        OE_RAISE_ERRNO(OE_EINVAL);

    for (int i = 0; i < iovcnt; i++)
    {
        const struct oe_iovec* p = &iov[i];
        ssize_t n;

        n = oe_read(fd, p->iov_base, p->iov_len);

        if (n < 0)
            goto done;

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
        OE_RAISE_ERRNO(OE_EINVAL);

    for (int i = 0; i < iovcnt; i++)
    {
        const struct oe_iovec* p = &iov[i];
        ssize_t n;

        n = oe_write(fd, p->iov_base, p->iov_len);

        if ((size_t)n != p->iov_len)
            OE_RAISE_ERRNO(OE_EIO);

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
        OE_RAISE_ERRNO(oe_errno);

    ret = fs->ops.fs.access(fs, suffix, mode);

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

        if (!(dev = oe_get_device(devid, OE_DEVICE_TYPE_FILE_SYSTEM)))
            OE_RAISE_ERRNO(OE_EINVAL);

        if (!pathname)
            OE_RAISE_ERRNO(OE_EINVAL);

        if (oe_stat(pathname, &buf) != 0)
            OE_RAISE_ERRNO(OE_ENOENT);

        ret = 0;
    }

done:
    return ret;
}
