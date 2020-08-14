// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/setjmp.h>
#include <openenclave/corelibc/stdarg.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/syscall/device.h>
#include <openenclave/internal/syscall/dirent.h>
#include <openenclave/internal/syscall/fcntl.h>
#include <openenclave/internal/syscall/raise.h>
#include <openenclave/internal/syscall/sys/ioctl.h>
#include <openenclave/internal/syscall/sys/mount.h>
#include <openenclave/internal/syscall/sys/poll.h>
#include <openenclave/internal/syscall/sys/select.h>
#include <openenclave/internal/syscall/sys/socket.h>
#include <openenclave/internal/syscall/sys/stat.h>
#include <openenclave/internal/syscall/sys/syscall.h>
#include <openenclave/internal/syscall/sys/uio.h>
#include <openenclave/internal/syscall/sys/utsname.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/internal/syscall_decls.h>
#include <openenclave/internal/trace.h>

typedef int (*ioctl_proc)(
    int fd,
    unsigned long request,
    long arg1,
    long arg2,
    long arg3,
    long arg4);

#define MARK_UNUSED() \
    OE_UNUSED(n + arg1 + arg2 + arg3 + arg4 + arg5 + arg6 + arg7)

OE_DEFINE_SYSCALL(OE_SYS_creat)
{
    MARK_UNUSED();
    long ret = -1;
    const char* pathname = (const char*)arg1;
    oe_mode_t mode = (oe_mode_t)arg2;
    int flags = (OE_O_CREAT | OE_O_WRONLY | OE_O_TRUNC);

    ret = oe_open(pathname, flags, mode);

    if (oe_errno == OE_ENOENT)
    {
        /* If the file was not found, give the caller (libc) a chance
         * to handle this syscall.
         */
        oe_errno = OE_ENOSYS;
        goto done;
    }

    goto done;
done:
    return ret;
}

OE_DEFINE_SYSCALL(OE_SYS_open)
{
    MARK_UNUSED();
    long ret = -1;

    const char* pathname = (const char*)arg1;
    int flags = (int)arg2;
    uint32_t mode = (uint32_t)arg3;

    ret = oe_open(pathname, flags, mode);

    if (ret < 0 && oe_errno == OE_ENOENT)
        goto done;

    goto done;
done:
    return ret;
}

OE_DEFINE_SYSCALL(OE_SYS_openat)
{
    MARK_UNUSED();
    long ret = -1;
    int dirfd = (int)arg1;
    const char* pathname = (const char*)arg2;
    int flags = (int)arg3;
    uint32_t mode = (uint32_t)arg4;

    if (dirfd != OE_AT_FDCWD)
    {
        oe_errno = OE_EBADF;
        goto done;
    }

    ret = oe_open(pathname, flags, mode);

    if (ret < 0 && oe_errno == OE_ENOENT)
        goto done;

    goto done;
done:
    return ret;
}

OE_DEFINE_SYSCALL(OE_SYS_close)
{
    MARK_UNUSED();
    int fd = (int)arg1;

    return oe_close(fd);
}

OE_DEFINE_SYSCALL(OE_SYS_lseek)
{
    MARK_UNUSED();
    int fd = (int)arg1;
    ssize_t off = (ssize_t)arg2;
    int whence = (int)arg3;
    return oe_lseek(fd, off, whence);
}

OE_DEFINE_SYSCALL(OE_SYS_pread64)
{
    MARK_UNUSED();
    const int fd = (int)arg1;
    void* const buf = (void*)arg2;
    const size_t count = (size_t)arg3;
    const oe_off_t offset = (oe_off_t)arg4;

    return oe_pread(fd, buf, count, offset);
}

OE_DEFINE_SYSCALL(OE_SYS_pwrite64)
{
    MARK_UNUSED();
    const int fd = (int)arg1;
    const void* const buf = (void*)arg2;
    const size_t count = (size_t)arg3;
    const oe_off_t offset = (oe_off_t)arg4;

    return oe_pwrite(fd, buf, count, offset);
}

OE_DEFINE_SYSCALL(OE_SYS_readv)
{
    MARK_UNUSED();
    int fd = (int)arg1;
    const struct oe_iovec* iov = (const struct oe_iovec*)arg2;
    int iovcnt = (int)arg3;

    return oe_readv(fd, iov, iovcnt);
}

OE_DEFINE_SYSCALL(OE_SYS_writev)
{
    MARK_UNUSED();
    int fd = (int)arg1;
    const struct oe_iovec* iov = (const struct oe_iovec*)arg2;
    int iovcnt = (int)arg3;

    return oe_writev(fd, iov, iovcnt);
}

OE_DEFINE_SYSCALL(OE_SYS_read)
{
    MARK_UNUSED();
    int fd = (int)arg1;
    void* buf = (void*)arg2;
    size_t count = (size_t)arg3;

    return oe_read(fd, buf, count);
}

OE_DEFINE_SYSCALL(OE_SYS_write)
{
    MARK_UNUSED();
    int fd = (int)arg1;
    const void* buf = (void*)arg2;
    size_t count = (size_t)arg3;

    return oe_write(fd, buf, count);
}

OE_DEFINE_SYSCALL(OE_SYS_dup)
{
    MARK_UNUSED();
    int fd = (int)arg1;

    return oe_dup(fd);
}

OE_DEFINE_SYSCALL(OE_SYS_flock)
{
    MARK_UNUSED();
    int fd = (int)arg1;
    int operation = (int)arg2;

    return oe_flock(fd, operation);
}

OE_DEFINE_SYSCALL(OE_SYS_fsync)
{
    MARK_UNUSED();
    const int fd = (int)arg1;

    return oe_fsync(fd);
}

OE_DEFINE_SYSCALL(OE_SYS_fdatasync)
{
    MARK_UNUSED();
    const int fd = (int)arg1;

    return oe_fdatasync(fd);
}

#if defined(OE_SYS_dup2)
OE_DEFINE_SYSCALL(OE_SYS_dup2)
{
    MARK_UNUSED();
    int oldfd = (int)arg1;
    int newfd = (int)arg2;

    return oe_dup2(oldfd, newfd);
}
#endif

OE_DEFINE_SYSCALL(OE_SYS_dup3)
{
    MARK_UNUSED();
    long ret = -1;
    int oldfd = (int)arg1;
    int newfd = (int)arg2;
    int flags = (int)arg3;

    if (flags != 0)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    ret = oe_dup2(oldfd, newfd);
done:
    return ret;
}

#if defined(OE_SYS_stat)
OE_DEFINE_SYSCALL(OE_SYS_stat)
{
    MARK_UNUSED();
    const char* pathname = (const char*)arg1;
    struct oe_stat_t* buf = (struct oe_stat_t*)arg2;
    return oe_stat(pathname, buf);
}
#endif

OE_DEFINE_SYSCALL(OE_SYS_newfstatat)
{
    MARK_UNUSED();
    long ret = -1;
    int dirfd = (int)arg1;
    const char* pathname = (const char*)arg2;
    struct oe_stat_t* buf = (struct oe_stat_t*)arg3;
    int flags = (int)arg4;

    if (dirfd != OE_AT_FDCWD)
    {
        oe_errno = OE_EBADF;
        goto done;
    }

    if (flags != 0)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    ret = oe_stat(pathname, buf);
done:
    return ret;
}

#if defined(OE_SYS_link)
OE_DEFINE_SYSCALL(OE_SYS_link)
{
    MARK_UNUSED();
    const char* oldpath = (const char*)arg1;
    const char* newpath = (const char*)arg2;
    return oe_link(oldpath, newpath);
}
#endif

OE_DEFINE_SYSCALL(OE_SYS_linkat)
{
    MARK_UNUSED();
    long ret = -1;
    int olddirfd = (int)arg1;
    const char* oldpath = (const char*)arg2;
    int newdirfd = (int)arg3;
    const char* newpath = (const char*)arg4;
    int flags = (int)arg5;

    if (olddirfd != OE_AT_FDCWD)
    {
        oe_errno = OE_EBADF;
        goto done;
    }

    if (newdirfd != OE_AT_FDCWD)
    {
        oe_errno = OE_EBADF;
        goto done;
    }

    if (flags != 0)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    ret = oe_link(oldpath, newpath);
done:
    goto done;
}

#if defined(OE_SYS_unlink)
OE_DEFINE_SYSCALL(OE_SYS_unlink)
{
    MARK_UNUSED();
    const char* pathname = (const char*)arg1;

    return oe_unlink(pathname);
}
#endif

OE_DEFINE_SYSCALL(OE_SYS_unlinkat)
{
    MARK_UNUSED();
    long ret = -1;
    int dirfd = (int)arg1;
    const char* pathname = (const char*)arg2;
    int flags = (int)arg3;

    if (dirfd != OE_AT_FDCWD)
    {
        oe_errno = OE_EBADF;
        goto done;
    }

    if (flags != OE_AT_REMOVEDIR && flags != 0)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    if (flags == OE_AT_REMOVEDIR)
        ret = oe_rmdir(pathname);
    else
        ret = oe_unlink(pathname);
done:
    return ret;
}

#if defined(OE_SYS_rename)
OE_DEFINE_SYSCALL(OE_SYS_rename)
{
    MARK_UNUSED();
    const char* oldpath = (const char*)arg1;
    const char* newpath = (const char*)arg2;

    return oe_rename(oldpath, newpath);
}
#endif

OE_DEFINE_SYSCALL(OE_SYS_renameat)
{
    MARK_UNUSED();
    long ret = -1;
    int olddirfd = (int)arg1;
    const char* oldpath = (const char*)arg2;
    int newdirfd = (int)arg3;
    const char* newpath = (const char*)arg4;
    int flags = (int)arg5;

    if (olddirfd != OE_AT_FDCWD)
    {
        oe_errno = OE_EBADF;
        goto done;
    }

    if (newdirfd != OE_AT_FDCWD)
    {
        oe_errno = OE_EBADF;
        goto done;
    }

    if (flags != 0)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    ret = oe_rename(oldpath, newpath);
done:
    return ret;
}

OE_DEFINE_SYSCALL(OE_SYS_truncate)
{
    MARK_UNUSED();
    const char* path = (const char*)arg1;
    ssize_t length = (ssize_t)arg2;

    return oe_truncate(path, length);
}

#if defined(OE_SYS_mkdir)
OE_DEFINE_SYSCALL(OE_SYS_mkdir)
{
    MARK_UNUSED();
    const char* pathname = (const char*)arg1;
    uint32_t mode = (uint32_t)arg2;

    return oe_mkdir(pathname, mode);
}
#endif

OE_DEFINE_SYSCALL(OE_SYS_mkdirat)
{
    MARK_UNUSED();
    long ret = -1;
    int dirfd = (int)arg1;
    const char* pathname = (const char*)arg2;
    uint32_t mode = (uint32_t)arg3;

    if (dirfd != OE_AT_FDCWD)
    {
        oe_errno = OE_EBADF;
        goto done;
    }

    ret = oe_mkdir(pathname, mode);
done:
    return ret;
}

#if defined(OE_SYS_rmdir)
OE_DEFINE_SYSCALL(OE_SYS_rmdir)
{
    MARK_UNUSED();
    const char* pathname = (const char*)arg1;
    return oe_rmdir(pathname);
}
#endif

#if defined(OE_SYS_access)
OE_DEFINE_SYSCALL(OE_SYS_access)
{
    MARK_UNUSED();
    const char* pathname = (const char*)arg1;
    int mode = (int)arg2;

    return oe_access(pathname, mode);
}
#endif

OE_DEFINE_SYSCALL(OE_SYS_faccessat)
{
    MARK_UNUSED();
    long ret = -1;
    int dirfd = (int)arg1;
    const char* pathname = (const char*)arg2;
    int mode = (int)arg3;
    int flags = (int)arg4;

    if (dirfd != OE_AT_FDCWD)
    {
        oe_errno = OE_EBADF;
        goto done;
    }

    if (flags != 0)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    ret = oe_access(pathname, mode);
done:
    return ret;
}

OE_DEFINE_SYSCALL(OE_SYS_getdents64)
{
    MARK_UNUSED();
    unsigned int fd = (unsigned int)arg1;
    struct oe_dirent* ent = (struct oe_dirent*)arg2;
    unsigned int count = (unsigned int)arg3;
    return oe_getdents64(fd, ent, count);
}

OE_DEFINE_SYSCALL(OE_SYS_ioctl)
{
    MARK_UNUSED();
    int fd = (int)arg1;
    unsigned long request = (unsigned long)arg2;
    long p1 = arg3;
    long p2 = arg4;
    long p3 = arg5;
    long p4 = arg6;

    return oe_ioctl(fd, request, p1, p2, p3, p4);
}

OE_DEFINE_SYSCALL(OE_SYS_fcntl)
{
    MARK_UNUSED();
    int fd = (int)arg1;
    int cmd = (int)arg2;
    uint64_t arg = (uint64_t)arg3;
    return oe_fcntl(fd, cmd, arg);
}

OE_DEFINE_SYSCALL(OE_SYS_mount)
{
    MARK_UNUSED();
    const char* source = (const char*)arg1;
    const char* target = (const char*)arg2;
    const char* fstype = (const char*)arg3;
    unsigned long flags = (unsigned long)arg4;
    void* data = (void*)arg5;

    return oe_mount(source, target, fstype, flags, data);
}

OE_DEFINE_SYSCALL(OE_SYS_umount2)
{
    MARK_UNUSED();
    const char* target = (const char*)arg1;
    int flags = (int)arg2;

    (void)flags;

    return oe_umount(target);
}

OE_DEFINE_SYSCALL(OE_SYS_getcwd)
{
    MARK_UNUSED();
    long ret = -1;
    char* buf = (char*)arg1;
    size_t size = (size_t)arg2;

    if (!oe_getcwd(buf, size))
    {
        ret = -1;
    }
    else
    {
        ret = (long)size;
    }

    return ret;
}

OE_DEFINE_SYSCALL(OE_SYS_chdir)
{
    MARK_UNUSED();
    char* path = (char*)arg1;

    return oe_chdir(path);
}

OE_DEFINE_SYSCALL(OE_SYS_socket)
{
    MARK_UNUSED();
    int domain = (int)arg1;
    int type = (int)arg2;
    int protocol = (int)arg3;
    return oe_socket(domain, type, protocol);
}

OE_DEFINE_SYSCALL(OE_SYS_connect)
{
    MARK_UNUSED();
    int sd = (int)arg1;
    const struct oe_sockaddr* addr = (const struct oe_sockaddr*)arg2;
    oe_socklen_t addrlen = (oe_socklen_t)arg3;
    return oe_connect(sd, addr, addrlen);
}

OE_DEFINE_SYSCALL(OE_SYS_setsockopt)
{
    MARK_UNUSED();
    int sockfd = (int)arg1;
    int level = (int)arg2;
    int optname = (int)arg3;
    void* optval = (void*)arg4;
    oe_socklen_t optlen = (oe_socklen_t)arg5;
    return oe_setsockopt(sockfd, level, optname, optval, optlen);
}

OE_DEFINE_SYSCALL(OE_SYS_getsockopt)
{
    MARK_UNUSED();
    int sockfd = (int)arg1;
    int level = (int)arg2;
    int optname = (int)arg3;
    void* optval = (void*)arg4;
    oe_socklen_t* optlen = (oe_socklen_t*)arg5;
    return oe_getsockopt(sockfd, level, optname, optval, optlen);
}

OE_DEFINE_SYSCALL(OE_SYS_getpeername)
{
    MARK_UNUSED();
    int sockfd = (int)arg1;
    struct sockaddr* addr = (struct sockaddr*)arg2;
    oe_socklen_t* addrlen = (oe_socklen_t*)arg3;
    return oe_getpeername(sockfd, (struct oe_sockaddr*)addr, addrlen);
}

OE_DEFINE_SYSCALL(OE_SYS_getsockname)
{
    MARK_UNUSED();
    int sockfd = (int)arg1;
    struct sockaddr* addr = (struct sockaddr*)arg2;
    oe_socklen_t* addrlen = (oe_socklen_t*)arg3;
    return oe_getsockname(sockfd, (struct oe_sockaddr*)addr, addrlen);
}

OE_DEFINE_SYSCALL(OE_SYS_bind)
{
    MARK_UNUSED();
    int sockfd = (int)arg1;
    struct oe_sockaddr* addr = (struct oe_sockaddr*)arg2;
    oe_socklen_t addrlen = (oe_socklen_t)arg3;
    return oe_bind(sockfd, addr, addrlen);
}

OE_DEFINE_SYSCALL(OE_SYS_listen)
{
    MARK_UNUSED();
    int sockfd = (int)arg1;
    int backlog = (int)arg2;
    return oe_listen(sockfd, backlog);
}

OE_DEFINE_SYSCALL(OE_SYS_accept)
{
    MARK_UNUSED();
    int sockfd = (int)arg1;
    struct oe_sockaddr* addr = (struct oe_sockaddr*)arg2;
    oe_socklen_t* addrlen = (oe_socklen_t*)arg3;
    return oe_accept(sockfd, addr, addrlen);
}

OE_DEFINE_SYSCALL(OE_SYS_sendto)
{
    MARK_UNUSED();
    int sockfd = (int)arg1;
    const void* buf = (void*)arg2;
    size_t len = (size_t)arg3;
    int flags = (int)arg4;
    const struct oe_sockaddr* dest_add = (const struct oe_sockaddr*)arg5;
    oe_socklen_t addrlen = (oe_socklen_t)arg6;

    return oe_sendto(sockfd, buf, len, flags, dest_add, addrlen);
}

OE_DEFINE_SYSCALL(OE_SYS_recvfrom)
{
    MARK_UNUSED();
    int sockfd = (int)arg1;
    void* buf = (void*)arg2;
    size_t len = (size_t)arg3;
    int flags = (int)arg4;
    const struct oe_sockaddr* dest_add = (const struct oe_sockaddr*)arg5;
    oe_socklen_t* addrlen = (oe_socklen_t*)arg6;

    return oe_recvfrom(sockfd, buf, len, flags, dest_add, addrlen);
}

OE_DEFINE_SYSCALL(OE_SYS_sendmsg)
{
    MARK_UNUSED();
    int sockfd = (int)arg1;
    struct msghdr* buf = (struct msghdr*)arg2;
    int flags = (int)arg3;

    return oe_sendmsg(sockfd, (struct oe_msghdr*)buf, flags);
}

OE_DEFINE_SYSCALL(OE_SYS_recvmsg)
{
    MARK_UNUSED();
    int sockfd = (int)arg1;
    struct msghdr* buf = (struct msghdr*)arg2;
    int flags = (int)arg3;

    return oe_recvmsg(sockfd, (struct oe_msghdr*)buf, flags);
}

OE_DEFINE_SYSCALL(OE_SYS_socketpair)
{
    MARK_UNUSED();
    int domain = (int)arg1;
    int type = (int)arg2;
    int protocol = (int)arg3;
    int* sv = (int*)arg4;

    return oe_socketpair(domain, type, protocol, sv);
}

OE_DEFINE_SYSCALL(OE_SYS_shutdown)
{
    MARK_UNUSED();
    int sockfd = (int)arg1;
    int how = (int)arg2;
    return oe_shutdown(sockfd, how);
}

OE_DEFINE_SYSCALL(OE_SYS_uname)
{
    MARK_UNUSED();
    struct oe_utsname* buf = (struct oe_utsname*)arg1;
    return oe_uname(buf);
}

#if defined(OE_SYS_select)
OE_DEFINE_SYSCALL(OE_SYS_select)
{
    MARK_UNUSED();
    int nfds = (int)arg1;
    oe_fd_set* readfds = (oe_fd_set*)arg2;
    oe_fd_set* writefds = (oe_fd_set*)arg3;
    oe_fd_set* efds = (oe_fd_set*)arg4;
    struct oe_timeval* timeout = (struct oe_timeval*)arg5;
    return oe_select(nfds, readfds, writefds, efds, timeout);
}
#endif

OE_DEFINE_SYSCALL(OE_SYS_pselect6)
{
    MARK_UNUSED();
    int nfds = (int)arg1;
    oe_fd_set* readfds = (oe_fd_set*)arg2;
    oe_fd_set* writefds = (oe_fd_set*)arg3;
    oe_fd_set* exceptfds = (oe_fd_set*)arg4;
    struct oe_timespec* ts = (struct oe_timespec*)arg5;
    struct oe_timeval buf;
    struct oe_timeval* tv = NULL;

    if (ts)
    {
        tv = &buf;
        tv->tv_sec = ts->tv_sec;
        tv->tv_usec = ts->tv_nsec / 1000;
    }

    return oe_select(nfds, readfds, writefds, exceptfds, tv);
}

#if defined(OE_SYS_poll)
OE_DEFINE_SYSCALL(OE_SYS_poll)
{
    MARK_UNUSED();
    struct oe_pollfd* fds = (struct oe_pollfd*)arg1;
    oe_nfds_t nfds = (oe_nfds_t)arg2;
    int millis = (int)arg3;
    return oe_poll(fds, nfds, millis);
}
#endif

OE_DEFINE_SYSCALL(OE_SYS_ppoll)
{
    MARK_UNUSED();
    long ret = -1;
    struct oe_pollfd* fds = (struct oe_pollfd*)arg1;
    oe_nfds_t nfds = (oe_nfds_t)arg2;
    struct oe_timespec* ts = (struct oe_timespec*)arg3;
    void* sigmask = (void*)arg4;
    int timeout = -1;

    if (sigmask != NULL)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    if (ts)
    {
        int64_t mul;
        int64_t div;
        int64_t sum;

        if (oe_safe_mul_s64(ts->tv_sec, 1000, &mul) != OE_OK)
        {
            oe_errno = OE_EINVAL;
            goto done;
        }

        div = ts->tv_nsec / 1000000;

        if (oe_safe_add_s64(mul, div, &sum) != OE_OK)
        {
            oe_errno = OE_EINVAL;
            goto done;
        }

        if (sum < OE_INT_MIN || sum > OE_INT_MAX)
        {
            oe_errno = OE_EINVAL;
            goto done;
        }

        timeout = (int)sum;
    }

    ret = oe_poll(fds, nfds, timeout);
done:
    return ret;
}

#if defined(OE_SYS_epoll_create)
OE_DEFINE_SYSCALL(OE_SYS_epoll_create)
{
    MARK_UNUSED();
    int size = (int)arg1;
    return oe_epoll_create(size);
}
#endif

OE_DEFINE_SYSCALL(OE_SYS_epoll_create1)
{
    MARK_UNUSED();
    int flags = (int)arg1;
    return oe_epoll_create1(flags);
}

#if defined(OE_SYS_epoll_wait)
OE_DEFINE_SYSCALL(OE_SYS_epoll_wait)
{
    MARK_UNUSED();
    int epfd = (int)arg1;
    struct oe_epoll_event* events = (struct oe_epoll_event*)arg2;
    int maxevents = (int)arg3;
    int timeout = (int)arg4;
    return oe_epoll_wait(epfd, events, maxevents, timeout);
}
#endif

OE_DEFINE_SYSCALL(OE_SYS_epoll_pwait)
{
    MARK_UNUSED();
    int epfd = (int)arg1;
    struct oe_epoll_event* events = (struct oe_epoll_event*)arg2;
    int maxevents = (int)arg3;
    int timeout = (int)arg4;
    const oe_sigset_t* sigmask = (const oe_sigset_t*)arg5;
    return oe_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
}

OE_DEFINE_SYSCALL(OE_SYS_epoll_ctl)
{
    MARK_UNUSED();
    int epfd = (int)arg1;
    int op = (int)arg2;
    int fd = (int)arg3;
    struct oe_epoll_event* event = (struct oe_epoll_event*)arg4;
    return oe_epoll_ctl(epfd, op, fd, event);
}

OE_DEFINE_SYSCALL(OE_SYS_exit_group)
{
    MARK_UNUSED();
    return 0;
}

OE_DEFINE_SYSCALL(OE_SYS_exit)
{
    MARK_UNUSED();
    int status = (int)arg1;
    oe_exit(status);
    // TODO: Is this correct return value.
    return -1;
}

OE_DEFINE_SYSCALL(OE_SYS_getpid)
{
    MARK_UNUSED();
    return (long)oe_getpid();
}

OE_DEFINE_SYSCALL(OE_SYS_getuid)
{
    MARK_UNUSED();
    return (long)oe_getuid();
}

OE_DEFINE_SYSCALL(OE_SYS_geteuid)
{
    MARK_UNUSED();
    return (long)oe_geteuid();
}

OE_DEFINE_SYSCALL(OE_SYS_getgid)
{
    MARK_UNUSED();
    return (long)oe_getgid();
}

OE_DEFINE_SYSCALL(OE_SYS_getpgid)
{
    MARK_UNUSED();
    int pid = (int)arg1;
    return (long)oe_getpgid(pid);
}

OE_DEFINE_SYSCALL(OE_SYS_getgroups)
{
    MARK_UNUSED();
    int size = (int)arg1;
    oe_gid_t* list = (oe_gid_t*)arg2;
    return (long)oe_getgroups(size, list);
}

OE_DEFINE_SYSCALL(OE_SYS_getegid)
{
    MARK_UNUSED();
    return (long)oe_getegid();
}

OE_DEFINE_SYSCALL(OE_SYS_getppid)
{
    MARK_UNUSED();
    return (long)oe_getppid();
}

#if defined(OE_SYS_getpgrp)
OE_DEFINE_SYSCALL(OE_SYS_getpgrp)
{
    MARK_UNUSED();
    return (long)oe_getpgrp();
}
#endif

OE_DEFINE_SYSCALL(OE_SYS_nanosleep)
{
    MARK_UNUSED();
    struct oe_timespec* req = (struct oe_timespec*)arg1;
    struct oe_timespec* rem = (struct oe_timespec*)arg2;
    return (long)oe_nanosleep(req, rem);
}

static long _syscall(
    long num,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5,
    long arg6)
{
    long ret = -1;
    oe_errno = 0;

    /* Handle the software system call. */
    switch (num)
    {
#if defined(OE_SYS_creat)
        case OE_SYS_creat:
            return OE_SYSCALL2(OE_SYS_creat, arg1, arg2);
#endif

#if defined(OE_SYS_open)
        case OE_SYS_open:
            return OE_SYSCALL3(OE_SYS_open, arg1, arg2, arg3);
#endif
        case OE_SYS_openat:
            return OE_SYSCALL4(OE_SYS_openat, arg1, arg2, arg3, arg4);

        case OE_SYS_lseek:
            return OE_SYSCALL3(OE_SYS_lseek, arg1, arg2, arg3);

        case OE_SYS_pread64:
            return OE_SYSCALL4(OE_SYS_pread64, arg1, arg2, arg3, arg4);

        case OE_SYS_pwrite64:
            return OE_SYSCALL4(OE_SYS_pwrite64, arg1, arg2, arg3, arg4);

        case OE_SYS_readv:
            return OE_SYSCALL3(OE_SYS_readv, arg1, arg2, arg3);

        case OE_SYS_writev:
            return OE_SYSCALL3(OE_SYS_writev, arg1, arg2, arg3);

        case OE_SYS_read:
            return OE_SYSCALL3(OE_SYS_read, arg1, arg2, arg3);

        case OE_SYS_write:
            return OE_SYSCALL3(OE_SYS_write, arg1, arg2, arg3);

        case OE_SYS_close:
            return OE_SYSCALL1(OE_SYS_close, arg1);

        case OE_SYS_dup:
            return OE_SYSCALL1(OE_SYS_dup, arg1);

        case OE_SYS_flock:
            return OE_SYSCALL2(OE_SYS_flock, arg1, arg2);

        case OE_SYS_fsync:
            return OE_SYSCALL1(OE_SYS_fsync, arg1);

        case OE_SYS_fdatasync:
            return OE_SYSCALL1(OE_SYS_fdatasync, arg1);

#if defined(OE_SYS_dup2)
        case OE_SYS_dup2:
            return OE_SYSCALL2(OE_SYS_dup2, arg1, arg2);
#endif

        case OE_SYS_dup3:
            return OE_SYSCALL3(OE_SYS_dup3, arg1, arg2, arg3);

#if defined(OE_SYS_stat)
        case OE_SYS_stat:
            return OE_SYSCALL2(OE_SYS_stat, arg1, arg2);
#endif

        case OE_SYS_newfstatat:
            return OE_SYSCALL3(OE_SYS_newfstatat, arg1, arg2, arg3);

#if defined(OE_SYS_link)
        case OE_SYS_link:
            return OE_SYSCALL2(OE_SYS_link, arg1, arg2);
#endif

        case OE_SYS_linkat:
            return OE_SYSCALL4(OE_SYS_linkat, arg1, arg2, arg3, arg4);

#if defined(OE_SYS_unlink)
        case OE_SYS_unlink:
            return OE_SYSCALL1(OE_SYS_unlink, arg1);
#endif

        case OE_SYS_unlinkat:
            return OE_SYSCALL3(OE_SYS_unlinkat, arg1, arg2, arg3);

#if defined(OE_SYS_rename)
        case OE_SYS_rename:
            return OE_SYSCALL2(OE_SYS_rename, arg1, arg2);
#endif

        case OE_SYS_renameat:
            return OE_SYSCALL5(OE_SYS_renameat, arg1, arg2, arg3, arg4, arg5);

        case OE_SYS_truncate:
            return OE_SYSCALL2(OE_SYS_truncate, arg1, arg2);

#if defined(OE_SYS_mkdir)
        case OE_SYS_mkdir:
            return OE_SYSCALL2(OE_SYS_mkdir, arg1, arg2);
#endif

        case OE_SYS_mkdirat:
            return OE_SYSCALL3(OE_SYS_mkdirat, arg1, arg2, arg3);

#if defined(OE_SYS_rmdir)
        case OE_SYS_rmdir:
            return OE_SYSCALL1(OE_SYS_rmdir, arg1);
#endif

#if defined(OE_SYS_access)
        case OE_SYS_access:
            return OE_SYSCALL1(OE_SYS_access, arg1);
#endif

        case OE_SYS_faccessat:
            return OE_SYSCALL4(OE_SYS_faccessat, arg1, arg2, arg3, arg4);

        case OE_SYS_getdents64:
            return OE_SYSCALL3(OE_SYS_getdents64, arg1, arg2, arg3);

        case OE_SYS_ioctl:
            return OE_SYSCALL6(
                OE_SYS_ioctl, arg1, arg2, arg3, arg4, arg5, arg6);

        case OE_SYS_fcntl:
            return OE_SYSCALL3(OE_SYS_fcntl, arg1, arg2, arg3);

        case OE_SYS_mount:
            return OE_SYSCALL3(OE_SYS_mount, arg1, arg2, arg3);

        case OE_SYS_umount2:
            return OE_SYSCALL1(OE_SYS_umount2, arg1);

        case OE_SYS_getcwd:
            return OE_SYSCALL2(OE_SYS_getcwd, arg1, arg2);

        case OE_SYS_chdir:
            return OE_SYSCALL1(OE_SYS_chdir, arg1);

        case OE_SYS_socket:
            return OE_SYSCALL3(OE_SYS_socket, arg1, arg2, arg3);

        case OE_SYS_connect:
            return OE_SYSCALL3(OE_SYS_connect, arg1, arg2, arg3);

        case OE_SYS_setsockopt:
            return OE_SYSCALL5(OE_SYS_setsockopt, arg1, arg2, arg3, arg4, arg5);

        case OE_SYS_getsockopt:
            return OE_SYSCALL5(OE_SYS_getsockopt, arg1, arg2, arg3, arg4, arg5);

        case OE_SYS_getpeername:
            return OE_SYSCALL3(OE_SYS_getpeername, arg1, arg2, arg3);

        case OE_SYS_getsockname:
            return OE_SYSCALL3(OE_SYS_getsockname, arg1, arg2, arg3);

        case OE_SYS_bind:
            return OE_SYSCALL3(OE_SYS_bind, arg1, arg2, arg3);

        case OE_SYS_listen:
            return OE_SYSCALL2(OE_SYS_listen, arg1, arg2);

        case OE_SYS_accept:
            return OE_SYSCALL3(OE_SYS_accept, arg1, arg2, arg3);

        case OE_SYS_sendto:
            return OE_SYSCALL6(
                OE_SYS_sendto, arg1, arg2, arg3, arg4, arg5, arg6);

        case OE_SYS_recvfrom:
            return OE_SYSCALL6(
                OE_SYS_recvfrom, arg1, arg2, arg3, arg4, arg5, arg6);

        case OE_SYS_sendmsg:
            return OE_SYSCALL3(OE_SYS_sendmsg, arg1, arg2, arg3);

        case OE_SYS_recvmsg:
            return OE_SYSCALL3(OE_SYS_recvmsg, arg1, arg2, arg3);

        case OE_SYS_socketpair:
            return OE_SYSCALL4(OE_SYS_socketpair, arg1, arg2, arg3, arg4);

        case OE_SYS_shutdown:
            return OE_SYSCALL2(OE_SYS_shutdown, arg1, arg2);

        case OE_SYS_uname:
            return OE_SYSCALL1(OE_SYS_uname, arg1);

#if defined(OE_SYS_select)
        case OE_SYS_select:
            return OE_SYSCALL5(OE_SYS_select, arg1, arg2, arg3, arg4, arg5);
#endif

        case OE_SYS_pselect6:
            return OE_SYSCALL5(OE_SYS_pselect6, arg1, arg2, arg3, arg4, arg5);

#if defined(OE_SYS_poll)
        case OE_SYS_poll:
            return OE_SYSCALL3(OE_SYS_poll, arg1, arg2, arg3);
#endif

        case OE_SYS_ppoll:
            return OE_SYSCALL3(OE_SYS_ppoll, arg1, arg2, arg3);

#if defined(OE_SYS_epoll_create)
        case OE_SYS_epoll_create:
            return OE_SYSCALL1(OE_SYS_epoll_create, arg1);
#endif

        case OE_SYS_epoll_create1:
            return OE_SYSCALL1(OE_SYS_epoll_create1, arg1);

#if defined(OE_SYS_epoll_wait)
        case OE_SYS_epoll_wait:
            return OE_SYSCALL4(OE_SYS_epoll_wait, arg1, arg2, arg3, arg4);

#endif
        case OE_SYS_epoll_pwait:
            return OE_SYSCALL5(
                OE_SYS_epoll_pwait, arg1, arg2, arg3, arg4, arg5);

        case OE_SYS_epoll_ctl:
            return OE_SYSCALL4(OE_SYS_epoll_ctl, arg1, arg2, arg3, arg4);

        case OE_SYS_exit_group:
            return OE_SYSCALL0(OE_SYS_exit_group);

        case OE_SYS_exit:
            return OE_SYSCALL1(OE_SYS_exit, arg1);

        case OE_SYS_getpid:
            return OE_SYSCALL0(OE_SYS_getpid);

        case OE_SYS_getuid:
            return OE_SYSCALL0(OE_SYS_getuid);

        case OE_SYS_geteuid:
            return OE_SYSCALL0(OE_SYS_geteuid);

        case OE_SYS_getgid:
            return OE_SYSCALL0(OE_SYS_getgid);

        case OE_SYS_getpgid:
            return OE_SYSCALL1(OE_SYS_getpgid, arg1);

        case OE_SYS_getgroups:
            return OE_SYSCALL2(OE_SYS_getgroups, arg1, arg2);

        case OE_SYS_getegid:
            return OE_SYSCALL0(OE_SYS_getegid);

        case OE_SYS_getppid:
            return OE_SYSCALL0(OE_SYS_getppid);

#if defined(OE_SYS_getpgrp)
        case OE_SYS_getpgrp:
            return OE_SYSCALL0(OE_SYS_getpgrp);

#endif
        case OE_SYS_nanosleep:
            return OE_SYSCALL2(OE_SYS_nanosleep, arg1, arg2);

        default:
        {
            oe_errno = OE_ENOSYS;
            OE_TRACE_WARNING("syscall num=%ld not handled", num);
            goto done;
        }
    }

    /* Unreachable */
done:
    return ret;
}

long oe_syscall(long number, ...)
{
    long ret;

    oe_va_list ap;
    oe_va_start(ap, number);
    long arg1 = oe_va_arg(ap, long);
    long arg2 = oe_va_arg(ap, long);
    long arg3 = oe_va_arg(ap, long);
    long arg4 = oe_va_arg(ap, long);
    long arg5 = oe_va_arg(ap, long);
    long arg6 = oe_va_arg(ap, long);
    ret = _syscall(number, arg1, arg2, arg3, arg4, arg5, arg6);
    oe_va_end(ap);

    return ret;
}
