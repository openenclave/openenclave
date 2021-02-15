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
#include <openenclave/internal/syscall/hook.h>
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
#include <openenclave/internal/trace.h>

typedef int (*ioctl_proc)(
    int fd,
    unsigned long request,
    long arg1,
    long arg2,
    long arg3,
    long arg4);

OE_WEAK OE_DEFINE_SYSCALL3_M(SYS_accept)
{
    oe_errno = 0;
    int sockfd = (int)arg1;
    struct oe_sockaddr* addr = (struct oe_sockaddr*)arg2;
    oe_socklen_t* addrlen = (oe_socklen_t*)arg3;
    return oe_accept(sockfd, addr, addrlen);
}

#if __x86_64__ || _M_X64
OE_WEAK OE_DEFINE_SYSCALL2(SYS_access)
{
    oe_errno = 0;
    const char* pathname = (const char*)arg1;
    int mode = (int)arg2;

    return oe_access(pathname, mode);
}
#endif

OE_WEAK OE_DEFINE_SYSCALL3_M(SYS_bind)
{
    oe_errno = 0;
    int sockfd = (int)arg1;
    struct oe_sockaddr* addr = (struct oe_sockaddr*)arg2;
    oe_socklen_t addrlen = (oe_socklen_t)arg3;
    return oe_bind(sockfd, addr, addrlen);
}

OE_WEAK OE_DEFINE_SYSCALL1(SYS_chdir)
{
    oe_errno = 0;
    char* path = (char*)arg1;

    return oe_chdir(path);
}

OE_WEAK OE_DEFINE_SYSCALL1_M(SYS_close)
{
    oe_errno = 0;
    int fd = (int)arg1;

    return oe_close(fd);
}

OE_WEAK OE_DEFINE_SYSCALL3_M(SYS_connect)
{
    oe_errno = 0;
    int sd = (int)arg1;
    const struct oe_sockaddr* addr = (const struct oe_sockaddr*)arg2;
    oe_socklen_t addrlen = (oe_socklen_t)arg3;
    return oe_connect(sd, addr, addrlen);
}

#if __x86_64__ || _M_X64
OE_WEAK OE_DEFINE_SYSCALL2(SYS_creat)
{
    oe_errno = 0;
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
    }

    return ret;
}
#endif

OE_WEAK OE_DEFINE_SYSCALL1(SYS_dup)
{
    oe_errno = 0;
    int fd = (int)arg1;

    return oe_dup(fd);
}

#if __x86_64__ || _M_X64
OE_WEAK OE_DEFINE_SYSCALL2(SYS_dup2)
{
    oe_errno = 0;
    int oldfd = (int)arg1;
    int newfd = (int)arg2;

    return oe_dup2(oldfd, newfd);
}
#endif

OE_WEAK OE_DEFINE_SYSCALL3(SYS_dup3)
{
    oe_errno = 0;
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

#if __x86_64__ || _M_X64
OE_WEAK OE_DEFINE_SYSCALL1(SYS_epoll_create)
{
    oe_errno = 0;
    int size = (int)arg1;
    return oe_epoll_create(size);
}
#endif

OE_WEAK OE_DEFINE_SYSCALL1(SYS_epoll_create1)
{
    oe_errno = 0;
    int flags = (int)arg1;
    return oe_epoll_create1(flags);
}

OE_WEAK OE_DEFINE_SYSCALL4(SYS_epoll_ctl)
{
    oe_errno = 0;
    int epfd = (int)arg1;
    int op = (int)arg2;
    int fd = (int)arg3;
    struct oe_epoll_event* event = (struct oe_epoll_event*)arg4;
    return oe_epoll_ctl(epfd, op, fd, event);
}

OE_WEAK OE_DEFINE_SYSCALL5_M(SYS_epoll_pwait)
{
    oe_errno = 0;
    int epfd = (int)arg1;
    struct oe_epoll_event* events = (struct oe_epoll_event*)arg2;
    int maxevents = (int)arg3;
    int timeout = (int)arg4;
    const oe_sigset_t* sigmask = (const oe_sigset_t*)arg5;
    return oe_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
}

#if __x86_64__ || _M_X64
OE_WEAK OE_DEFINE_SYSCALL4_M(SYS_epoll_wait)
{
    oe_errno = 0;
    int epfd = (int)arg1;
    struct oe_epoll_event* events = (struct oe_epoll_event*)arg2;
    int maxevents = (int)arg3;
    int timeout = (int)arg4;
    return oe_epoll_wait(epfd, events, maxevents, timeout);
}
#endif

OE_WEAK OE_DEFINE_SYSCALL1(SYS_exit)
{
    oe_errno = 0;
    int status = (int)arg1;
    oe_exit(status);

    // Control does not reach here.
    asm volatile("ud2");
    return -1;
}

OE_WEAK OE_DEFINE_SYSCALL1(SYS_exit_group)
{
    OE_UNUSED(arg1);
    oe_errno = 0;
    return 0;
}

OE_WEAK OE_DEFINE_SYSCALL4(SYS_faccessat)
{
    oe_errno = 0;
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

OE_WEAK OE_DEFINE_SYSCALL2_M(SYS_fcntl)
{
    oe_va_list ap;
    oe_va_start(ap, arg2);
    long arg3 = oe_va_arg(ap, long);
    oe_va_end(ap);

    oe_errno = 0;
    int fd = (int)arg1;
    int cmd = (int)arg2;
    uint64_t arg = (uint64_t)arg3;

    return oe_fcntl(fd, cmd, arg);
}

OE_WEAK OE_DEFINE_SYSCALL1_M(SYS_fdatasync)
{
    oe_errno = 0;
    const int fd = (int)arg1;

    return oe_fdatasync(fd);
}

OE_WEAK OE_DEFINE_SYSCALL2(SYS_flock)
{
    oe_errno = 0;
    int fd = (int)arg1;
    int operation = (int)arg2;

    return oe_flock(fd, operation);
}

OE_WEAK OE_DEFINE_SYSCALL2(SYS_fstat)
{
    oe_errno = 0;
    const int fd = (int)arg1;
    struct oe_stat_t* const buf = (struct oe_stat_t*)arg2;
    return oe_fstat(fd, buf);
}

OE_WEAK OE_DEFINE_SYSCALL4(SYS_fstatat)
{
    oe_errno = 0;
    long ret = -1;
    int dirfd = (int)arg1;
    const char* pathname = (const char*)arg2;
    struct oe_stat_t* stat = (struct oe_stat_t*)arg3;
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

    ret = oe_stat(pathname, stat);
done:
    return ret;
}

OE_WEAK OE_DEFINE_SYSCALL1_M(SYS_fsync)
{
    oe_errno = 0;
    const int fd = (int)arg1;

    return oe_fsync(fd);
}

OE_WEAK OE_DEFINE_SYSCALL2(SYS_ftruncate)
{
    oe_errno = 0;
    const int fd = (int)arg1;
    const ssize_t length = (ssize_t)arg2;
    return oe_ftruncate(fd, length);
}

OE_WEAK OE_DEFINE_SYSCALL3_M(SYS_futex)
{
    OE_UNUSED(arg1);
    OE_UNUSED(arg2);
    OE_UNUSED(arg3);
    return -1;
}

OE_WEAK OE_DEFINE_SYSCALL2(SYS_getcwd)
{
    oe_errno = 0;
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

OE_WEAK OE_DEFINE_SYSCALL3(SYS_getdents)
{
    oe_errno = 0;
    unsigned int fd = (unsigned int)arg1;
    struct oe_dirent* ent = (struct oe_dirent*)arg2;
    unsigned int count = (unsigned int)arg3;
    return oe_getdents64(fd, ent, count);
}

OE_WEAK OE_DEFINE_SYSCALL3(SYS_getdents64)
{
    oe_errno = 0;
    unsigned int fd = (unsigned int)arg1;
    struct oe_dirent* ent = (struct oe_dirent*)arg2;
    unsigned int count = (unsigned int)arg3;
    return oe_getdents64(fd, ent, count);
}

OE_WEAK OE_DEFINE_SYSCALL0(SYS_getegid)
{
    oe_errno = 0;
    return (long)oe_getegid();
}

OE_WEAK OE_DEFINE_SYSCALL0(SYS_geteuid)
{
    oe_errno = 0;
    return (long)oe_geteuid();
}

OE_WEAK OE_DEFINE_SYSCALL2(SYS_getgroups)
{
    oe_errno = 0;
    int size = (int)arg1;
    oe_gid_t* list = (oe_gid_t*)arg2;
    return (long)oe_getgroups(size, list);
}

OE_WEAK OE_DEFINE_SYSCALL3_M(SYS_getpeername)
{
    oe_errno = 0;
    int sockfd = (int)arg1;
    struct sockaddr* addr = (struct sockaddr*)arg2;
    oe_socklen_t* addrlen = (oe_socklen_t*)arg3;
    return oe_getpeername(sockfd, (struct oe_sockaddr*)addr, addrlen);
}

OE_WEAK OE_DEFINE_SYSCALL1(SYS_getpgid)
{
    oe_errno = 0;
    int pid = (int)arg1;
    return (long)oe_getpgid(pid);
}

#if __x86_64__ || _M_X64
OE_WEAK OE_DEFINE_SYSCALL0(SYS_getpgrp)
{
    oe_errno = 0;
    return (long)oe_getpgrp();
}
#endif

OE_WEAK OE_DEFINE_SYSCALL0(SYS_getpid)
{
    oe_errno = 0;
    return (long)oe_getpid();
}

OE_WEAK OE_DEFINE_SYSCALL0(SYS_getgid)
{
    oe_errno = 0;
    return (long)oe_getgid();
}

OE_WEAK OE_DEFINE_SYSCALL0(SYS_getppid)
{
    oe_errno = 0;
    return (long)oe_getppid();
}

OE_WEAK OE_DEFINE_SYSCALL3_M(SYS_getsockname)
{
    oe_errno = 0;
    int sockfd = (int)arg1;
    struct sockaddr* addr = (struct sockaddr*)arg2;
    oe_socklen_t* addrlen = (oe_socklen_t*)arg3;
    return oe_getsockname(sockfd, (struct oe_sockaddr*)addr, addrlen);
}

OE_WEAK OE_DEFINE_SYSCALL5_M(SYS_getsockopt)
{
    oe_errno = 0;
    int sockfd = (int)arg1;
    int level = (int)arg2;
    int optname = (int)arg3;
    void* optval = (void*)arg4;
    oe_socklen_t* optlen = (oe_socklen_t*)arg5;
    return oe_getsockopt(sockfd, level, optname, optval, optlen);
}

OE_WEAK OE_DEFINE_SYSCALL0(SYS_getuid)
{
    oe_errno = 0;
    return (long)oe_getuid();
}

OE_WEAK OE_DEFINE_SYSCALL3_M(SYS_ioctl)
{
    oe_va_list ap;
    oe_va_start(ap, arg3);
    long arg4 = oe_va_arg(ap, long);
    long arg5 = oe_va_arg(ap, long);
    long arg6 = oe_va_arg(ap, long);
    oe_va_end(ap);

    oe_errno = 0;
    int fd = (int)arg1;
    unsigned long request = (unsigned long)arg2;
    long p1 = arg3;
    long p2 = arg4;
    long p3 = arg5;
    long p4 = arg6;

    return oe_ioctl(fd, request, p1, p2, p3, p4);
}

#if __x86_64__ || _M_X64
OE_WEAK OE_DEFINE_SYSCALL2(SYS_link)
{
    oe_errno = 0;
    const char* oldpath = (const char*)arg1;
    const char* newpath = (const char*)arg2;
    return oe_link(oldpath, newpath);
}
#endif

OE_WEAK OE_DEFINE_SYSCALL5(SYS_linkat)
{
    oe_errno = 0;
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
    return ret;
}

OE_WEAK OE_DEFINE_SYSCALL2_M(SYS_listen)
{
    oe_errno = 0;
    int sockfd = (int)arg1;
    int backlog = (int)arg2;
    return oe_listen(sockfd, backlog);
}

OE_WEAK OE_WEAK OE_DEFINE_SYSCALL3(SYS_lseek)
{
    oe_errno = 0;
    int fd = (int)arg1;
    ssize_t off = (ssize_t)arg2;
    int whence = (int)arg3;
    return oe_lseek(fd, off, whence);
}

#if __x86_64__ || _M_X64
OE_WEAK OE_DEFINE_SYSCALL2(SYS_mkdir)
{
    oe_errno = 0;
    const char* pathname = (const char*)arg1;
    uint32_t mode = (uint32_t)arg2;

    return oe_mkdir(pathname, mode);
}
#endif

OE_WEAK OE_DEFINE_SYSCALL3(SYS_mkdirat)
{
    oe_errno = 0;
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

OE_WEAK OE_DEFINE_SYSCALL5(SYS_mount)
{
    oe_errno = 0;
    const char* source = (const char*)arg1;
    const char* target = (const char*)arg2;
    const char* fstype = (const char*)arg3;
    unsigned long flags = (unsigned long)arg4;
    void* data = (void*)arg5;

    return oe_mount(source, target, fstype, flags, data);
}

OE_WEAK OE_DEFINE_SYSCALL2_M(SYS_nanosleep)
{
    oe_errno = 0;
    struct oe_timespec* req = (struct oe_timespec*)arg1;
    struct oe_timespec* rem = (struct oe_timespec*)arg2;
    return (long)oe_nanosleep(req, rem);
}

OE_WEAK OE_DEFINE_SYSCALL4(SYS_newfstatat)
{
    oe_errno = 0;
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

#if __x86_64__ || _M_X64
OE_WEAK OE_DEFINE_SYSCALL2_M(SYS_open)
{
    oe_va_list ap;
    oe_va_start(ap, arg2);
    long arg3 = oe_va_arg(ap, long);
    oe_va_end(ap);

    oe_errno = 0;
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
#endif

OE_WEAK OE_DEFINE_SYSCALL2_M(SYS_openat)
{
    oe_va_list ap;
    oe_va_start(ap, arg2);
    long arg3 = oe_va_arg(ap, long);
    long arg4 = oe_va_arg(ap, long);
    oe_va_end(ap);

    oe_errno = 0;
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

#if __x86_64__ || _M_X64
OE_WEAK OE_DEFINE_SYSCALL3_M(SYS_poll)
{
    oe_errno = 0;
    struct oe_pollfd* fds = (struct oe_pollfd*)arg1;
    oe_nfds_t nfds = (oe_nfds_t)arg2;
    int millis = (int)arg3;
    return oe_poll(fds, nfds, millis);
}
#endif

OE_WEAK OE_DEFINE_SYSCALL4_M(SYS_ppoll)
{
    oe_errno = 0;
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

OE_WEAK OE_DEFINE_SYSCALL4_M(SYS_pread)
{
    oe_errno = 0;
    const int fd = (int)arg1;
    void* const buf = (void*)arg2;
    const size_t count = (size_t)arg3;
    const oe_off_t offset = (oe_off_t)arg4;

    return oe_pread(fd, buf, count, offset);
}

OE_WEAK OE_DEFINE_SYSCALL4(SYS_pread64)
{
    oe_errno = 0;
    const int fd = (int)arg1;
    void* const buffer = (void*)arg2;
    const size_t count = (size_t)arg3;
    const oe_off_t offset = (oe_off_t)arg4;

    return oe_pread(fd, buffer, count, offset);
}

OE_WEAK OE_DEFINE_SYSCALL5_M(SYS_pselect6)
{
    oe_errno = 0;
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

OE_WEAK OE_DEFINE_SYSCALL4_M(SYS_pwrite)
{
    oe_errno = 0;
    const int fd = (int)arg1;
    const void* const buffer = (void*)arg2;
    const size_t count = (size_t)arg3;
    const oe_off_t offset = (oe_off_t)arg4;

    return oe_pwrite(fd, buffer, count, offset);
}

OE_WEAK OE_DEFINE_SYSCALL4(SYS_pwrite64)
{
    oe_errno = 0;
    const int fd = (int)arg1;
    const void* const buf = (void*)arg2;
    const size_t count = (size_t)arg3;
    const oe_off_t offset = (oe_off_t)arg4;

    return oe_pwrite(fd, buf, count, offset);
}

OE_WEAK OE_DEFINE_SYSCALL3_M(SYS_read)
{
    oe_errno = 0;
    int fd = (int)arg1;
    void* buf = (void*)arg2;
    size_t count = (size_t)arg3;

    return oe_read(fd, buf, count);
}

OE_WEAK OE_DEFINE_SYSCALL3_M(SYS_readv)
{
    oe_errno = 0;
    int fd = (int)arg1;
    const struct oe_iovec* iov = (const struct oe_iovec*)arg2;
    int iovcnt = (int)arg3;

    return oe_readv(fd, iov, iovcnt);
}

OE_WEAK OE_DEFINE_SYSCALL6(SYS_recvfrom)
{
    oe_errno = 0;
    int sockfd = (int)arg1;
    void* buf = (void*)arg2;
    size_t len = (size_t)arg3;
    int flags = (int)arg4;
    struct oe_sockaddr* dest_add = (struct oe_sockaddr*)arg5;
    oe_socklen_t* addrlen = (oe_socklen_t*)arg6;

    return oe_recvfrom(sockfd, buf, len, flags, dest_add, addrlen);
}

OE_WEAK OE_DEFINE_SYSCALL3_M(SYS_recvmsg)
{
    oe_errno = 0;
    int sockfd = (int)arg1;
    struct msghdr* buf = (struct msghdr*)arg2;
    int flags = (int)arg3;

    return oe_recvmsg(sockfd, (struct oe_msghdr*)buf, flags);
}

#if __x86_64__ || _M_X64
OE_WEAK OE_DEFINE_SYSCALL2(SYS_rename)
{
    oe_errno = 0;
    const char* oldpath = (const char*)arg1;
    const char* newpath = (const char*)arg2;

    return oe_rename(oldpath, newpath);
}
#endif

OE_WEAK OE_DEFINE_SYSCALL4_M(SYS_renameat)
{
    oe_va_list ap;
    oe_va_start(ap, arg4);
    long arg5 = oe_va_arg(ap, long);
    oe_va_end(ap);

    oe_errno = 0;
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

#if __x86_64__ || _M_X64
OE_WEAK OE_DEFINE_SYSCALL1(SYS_rmdir)
{
    oe_errno = 0;
    const char* pathname = (const char*)arg1;
    return oe_rmdir(pathname);
}
#endif

#if __x86_64__ || _M_X64
OE_WEAK OE_DEFINE_SYSCALL5_M(SYS_select)
{
    oe_errno = 0;
    int nfds = (int)arg1;
    oe_fd_set* readfds = (oe_fd_set*)arg2;
    oe_fd_set* writefds = (oe_fd_set*)arg3;
    oe_fd_set* efds = (oe_fd_set*)arg4;
    struct oe_timeval* timeout = (struct oe_timeval*)arg5;
    return oe_select(nfds, readfds, writefds, efds, timeout);
}
#endif

OE_WEAK OE_DEFINE_SYSCALL6(SYS_sendto)
{
    oe_errno = 0;
    int sockfd = (int)arg1;
    const void* buf = (void*)arg2;
    size_t len = (size_t)arg3;
    int flags = (int)arg4;
    const struct oe_sockaddr* dest_add = (const struct oe_sockaddr*)arg5;
    oe_socklen_t addrlen = (oe_socklen_t)arg6;

    return oe_sendto(sockfd, buf, len, flags, dest_add, addrlen);
}

OE_WEAK OE_DEFINE_SYSCALL3_M(SYS_sendmsg)
{
    oe_errno = 0;
    int sockfd = (int)arg1;
    struct msghdr* buf = (struct msghdr*)arg2;
    int flags = (int)arg3;

    return oe_sendmsg(sockfd, (struct oe_msghdr*)buf, flags);
}

OE_WEAK OE_DEFINE_SYSCALL5_M(SYS_setsockopt)
{
    oe_errno = 0;
    int sockfd = (int)arg1;
    int level = (int)arg2;
    int optname = (int)arg3;
    void* optval = (void*)arg4;
    oe_socklen_t optlen = (oe_socklen_t)arg5;
    return oe_setsockopt(sockfd, level, optname, optval, optlen);
}

OE_WEAK OE_DEFINE_SYSCALL2_M(SYS_shutdown)
{
    oe_errno = 0;
    int sockfd = (int)arg1;
    int how = (int)arg2;
    return oe_shutdown(sockfd, how);
}

OE_WEAK OE_DEFINE_SYSCALL3_M(SYS_socket)
{
    oe_errno = 0;
    int domain = (int)arg1;
    int type = (int)arg2;
    int protocol = (int)arg3;
    return oe_socket(domain, type, protocol);
}

OE_WEAK OE_DEFINE_SYSCALL4_M(SYS_socketpair)
{
    oe_errno = 0;
    int domain = (int)arg1;
    int type = (int)arg2;
    int protocol = (int)arg3;
    int* sv = (int*)arg4;

    return oe_socketpair(domain, type, protocol, sv);
}

#if __x86_64__ || _M_X64
OE_WEAK OE_DEFINE_SYSCALL2(SYS_stat)
{
    oe_errno = 0;
    const char* pathname = (const char*)arg1;
    struct oe_stat_t* buf = (struct oe_stat_t*)arg2;
    return oe_stat(pathname, buf);
}
#endif

OE_WEAK OE_DEFINE_SYSCALL2(SYS_truncate)
{
    oe_errno = 0;
    const char* path = (const char*)arg1;
    ssize_t length = (ssize_t)arg2;

    return oe_truncate(path, length);
}

OE_WEAK OE_DEFINE_SYSCALL3_M(SYS_write)
{
    oe_errno = 0;
    int fd = (int)arg1;
    const void* buf = (void*)arg2;
    size_t count = (size_t)arg3;

    return oe_write(fd, buf, count);
}

OE_WEAK OE_DEFINE_SYSCALL3_M(SYS_writev)
{
    oe_errno = 0;
    int fd = (int)arg1;
    const struct oe_iovec* iov = (const struct oe_iovec*)arg2;
    int iovcnt = (int)arg3;

    return oe_writev(fd, iov, iovcnt);
}

OE_WEAK OE_DEFINE_SYSCALL1(SYS_uname)
{
    oe_errno = 0;
    struct oe_utsname* buf = (struct oe_utsname*)arg1;
    return oe_uname(buf);
}

#if __x86_64__ || _M_X64
OE_WEAK OE_DEFINE_SYSCALL1(SYS_unlink)
{
    oe_errno = 0;
    const char* pathname = (const char*)arg1;

    return oe_unlink(pathname);
}
#endif

OE_WEAK OE_DEFINE_SYSCALL3(SYS_unlinkat)
{
    oe_errno = 0;
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

OE_WEAK OE_DEFINE_SYSCALL2(SYS_umount2)
{
    oe_errno = 0;
    const char* target = (const char*)arg1;
    int flags = (int)arg2;

    (void)flags;

    return oe_umount(target);
}

static long _syscall(
    long number,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5,
    long arg6)
{
    // Each of the syscall implementation functions must set oe_errno correctly
    // since they can be called directly, bypassing this _sycall dispatching
    // function.

    switch (number)
    {
        OE_SYSCALL_DISPATCH(SYS_accept, arg1, arg2, arg3);
#if __x86_64__ || _M_X64
        OE_SYSCALL_DISPATCH(SYS_access, arg1, arg2);
#endif
        OE_SYSCALL_DISPATCH(SYS_bind, arg1, arg2, arg3);
        OE_SYSCALL_DISPATCH(SYS_chdir, arg1);
        OE_SYSCALL_DISPATCH(SYS_close, arg1);
        OE_SYSCALL_DISPATCH(SYS_connect, arg1, arg2, arg3);
#if __x86_64__ || _M_X64
        OE_SYSCALL_DISPATCH(SYS_creat, arg1, arg2);
#endif
        OE_SYSCALL_DISPATCH(SYS_dup, arg1);
#if __x86_64__ || _M_X64
        OE_SYSCALL_DISPATCH(SYS_dup2, arg1, arg2);
#endif
        OE_SYSCALL_DISPATCH(SYS_dup3, arg1, arg2, arg3);
#if __x86_64__ || _M_X64
        OE_SYSCALL_DISPATCH(SYS_epoll_create, arg1);
#endif
        OE_SYSCALL_DISPATCH(SYS_epoll_create1, arg1);
        OE_SYSCALL_DISPATCH(SYS_epoll_ctl, arg1, arg2, arg3, arg4);
        OE_SYSCALL_DISPATCH(SYS_epoll_pwait, arg1, arg2, arg3, arg4, arg5);
#if __x86_64__ || _M_X64
        OE_SYSCALL_DISPATCH(SYS_epoll_wait, arg1, arg2, arg3, arg4);
#endif
        OE_SYSCALL_DISPATCH(SYS_exit, arg1);
        OE_SYSCALL_DISPATCH(SYS_exit_group, arg1);
        OE_SYSCALL_DISPATCH(SYS_faccessat, arg1, arg2, arg3, arg4);
        OE_SYSCALL_DISPATCH(SYS_fcntl, arg1, arg2, arg3, arg4);
        OE_SYSCALL_DISPATCH(SYS_fdatasync, arg1);
        OE_SYSCALL_DISPATCH(SYS_flock, arg1, arg2);
        OE_SYSCALL_DISPATCH(SYS_fstat, arg1, arg2);
        OE_SYSCALL_DISPATCH(SYS_fsync, arg1);
        OE_SYSCALL_DISPATCH(SYS_ftruncate, arg1, arg2);
        OE_SYSCALL_DISPATCH(SYS_getcwd, arg1, arg2);
        OE_SYSCALL_DISPATCH(SYS_getdents64, arg1, arg2, arg3);
        OE_SYSCALL_DISPATCH(SYS_getegid);
        OE_SYSCALL_DISPATCH(SYS_geteuid);
        OE_SYSCALL_DISPATCH(SYS_getgid);
        OE_SYSCALL_DISPATCH(SYS_getgroups, arg1, arg2);
        OE_SYSCALL_DISPATCH(SYS_getpeername, arg1, arg2, arg3);
        OE_SYSCALL_DISPATCH(SYS_getpgid, arg1);
#if __x86_64__ || _M_X64
        OE_SYSCALL_DISPATCH(SYS_getpgrp);
#endif
        OE_SYSCALL_DISPATCH(SYS_getpid);
        OE_SYSCALL_DISPATCH(SYS_getppid);
        OE_SYSCALL_DISPATCH(SYS_getsockname, arg1, arg2, arg3);
        OE_SYSCALL_DISPATCH(SYS_getsockopt, arg1, arg2, arg3, arg4, arg5);
        OE_SYSCALL_DISPATCH(SYS_getuid);
        OE_SYSCALL_DISPATCH(SYS_ioctl, arg1, arg2, arg3, arg4, arg5, arg6);
#if __x86_64__ || _M_X64
        OE_SYSCALL_DISPATCH(SYS_link, arg1, arg2);
#endif
        OE_SYSCALL_DISPATCH(SYS_linkat, arg1, arg2, arg3, arg4, arg5);
        OE_SYSCALL_DISPATCH(SYS_listen, arg1, arg2);
        OE_SYSCALL_DISPATCH(SYS_lseek, arg1, arg2, arg3);
#if __x86_64__ || _M_X64
        OE_SYSCALL_DISPATCH(SYS_mkdir, arg1, arg2);
#endif
        OE_SYSCALL_DISPATCH(SYS_mkdirat, arg1, arg2, arg3);
        OE_SYSCALL_DISPATCH(SYS_mount, arg1, arg2, arg3, arg4, arg5);
        OE_SYSCALL_DISPATCH(SYS_nanosleep, arg1, arg2);
        OE_SYSCALL_DISPATCH(SYS_newfstatat, arg1, arg2, arg3, arg4);
#if __x86_64__ || _M_X64
        OE_SYSCALL_DISPATCH(SYS_open, arg1, arg2, arg3);
#endif
        OE_SYSCALL_DISPATCH(SYS_openat, arg1, arg2, arg3, arg4);
#if __x86_64__ || _M_X64
        OE_SYSCALL_DISPATCH(SYS_poll, arg1, arg2, arg3);
#endif
        OE_SYSCALL_DISPATCH(SYS_ppoll, arg1, arg2, arg3, arg4);
        OE_SYSCALL_DISPATCH(SYS_pread64, arg1, arg2, arg3, arg4);
        // TODO Issue #3580: Implement 6 argument version of pselect
        OE_SYSCALL_DISPATCH(SYS_pselect6, arg1, arg2, arg3, arg4, arg5);
        OE_SYSCALL_DISPATCH(SYS_pwrite64, arg1, arg2, arg3, arg4);
        OE_SYSCALL_DISPATCH(SYS_read, arg1, arg2, arg3);
        OE_SYSCALL_DISPATCH(SYS_readv, arg1, arg2, arg3);
        OE_SYSCALL_DISPATCH(SYS_recvfrom, arg1, arg2, arg3, arg4, arg5, arg6);
        OE_SYSCALL_DISPATCH(SYS_recvmsg, arg1, arg2, arg3);
#if __x86_64__ || _M_X64
        OE_SYSCALL_DISPATCH(SYS_rename, arg1, arg2);
#endif
        OE_SYSCALL_DISPATCH(SYS_renameat, arg1, arg2, arg3, arg4, arg5);
#if __x86_64__ || _M_X64
        OE_SYSCALL_DISPATCH(SYS_rmdir, arg1);
#endif
#if __x86_64__ || _M_X64
        OE_SYSCALL_DISPATCH(SYS_select, arg1, arg2, arg3, arg4, arg5);
#endif
        OE_SYSCALL_DISPATCH(SYS_sendto, arg1, arg2, arg3, arg4, arg5, arg6);
        OE_SYSCALL_DISPATCH(SYS_sendmsg, arg1, arg2, arg3);
        OE_SYSCALL_DISPATCH(SYS_setsockopt, arg1, arg2, arg3, arg4, arg5);
        OE_SYSCALL_DISPATCH(SYS_shutdown, arg1, arg2);
        OE_SYSCALL_DISPATCH(SYS_socket, arg1, arg2, arg3);
        OE_SYSCALL_DISPATCH(SYS_socketpair, arg1, arg2, arg3, arg4);
#if __x86_64__ || _M_X64
        OE_SYSCALL_DISPATCH(SYS_stat, arg1, arg2);
#endif
        OE_SYSCALL_DISPATCH(SYS_truncate, arg1, arg2);
        OE_SYSCALL_DISPATCH(SYS_write, arg1, arg2, arg3);
        OE_SYSCALL_DISPATCH(SYS_writev, arg1, arg2, arg3);
        OE_SYSCALL_DISPATCH(SYS_uname, arg1);
#if __x86_64__ || _M_X64
        OE_SYSCALL_DISPATCH(SYS_unlink, arg1);
#endif
        OE_SYSCALL_DISPATCH(SYS_unlinkat, arg1, arg2, arg3);
        OE_SYSCALL_DISPATCH(SYS_umount2, arg1, arg2);
    }

    oe_errno = OE_ENOSYS;
    OE_TRACE_WARNING("syscall num=%ld not handled", number);
    return -1;
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
    oe_va_end(ap);
    ret = _syscall(number, arg1, arg2, arg3, arg4, arg5, arg6);

    return ret;
}
