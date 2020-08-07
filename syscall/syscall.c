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
#include <openenclave/internal/trace.h>

typedef int (*ioctl_proc)(
    int fd,
    unsigned long request,
    long arg1,
    long arg2,
    long arg3,
    long arg4);

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
        {
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
        }
#endif
#if defined(OE_SYS_open)
        case OE_SYS_open:
        {
            const char* pathname = (const char*)arg1;
            int flags = (int)arg2;
            uint32_t mode = (uint32_t)arg3;

            ret = oe_open(pathname, flags, mode);

            if (ret < 0 && oe_errno == OE_ENOENT)
                goto done;

            goto done;
        }
#endif
        case OE_SYS_openat:
        {
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
        }
        case OE_SYS_lseek:
        {
            int fd = (int)arg1;
            ssize_t off = (ssize_t)arg2;
            int whence = (int)arg3;
            ret = oe_lseek(fd, off, whence);
            goto done;
        }
        case OE_SYS_pread64:
        {
            const int fd = (int)arg1;
            void* const buf = (void*)arg2;
            const size_t count = (size_t)arg3;
            const oe_off_t offset = (oe_off_t)arg4;

            ret = oe_pread(fd, buf, count, offset);
            goto done;
        }
        case OE_SYS_pwrite64:
        {
            const int fd = (int)arg1;
            const void* const buf = (void*)arg2;
            const size_t count = (size_t)arg3;
            const oe_off_t offset = (oe_off_t)arg4;

            ret = oe_pwrite(fd, buf, count, offset);
            goto done;
        }
        case OE_SYS_readv:
        {
            int fd = (int)arg1;
            const struct oe_iovec* iov = (const struct oe_iovec*)arg2;
            int iovcnt = (int)arg3;

            ret = oe_readv(fd, iov, iovcnt);
            goto done;
        }
        case OE_SYS_writev:
        {
            int fd = (int)arg1;
            const struct oe_iovec* iov = (const struct oe_iovec*)arg2;
            int iovcnt = (int)arg3;

            ret = oe_writev(fd, iov, iovcnt);
            goto done;
        }
        case OE_SYS_read:
        {
            int fd = (int)arg1;
            void* buf = (void*)arg2;
            size_t count = (size_t)arg3;

            ret = oe_read(fd, buf, count);
            goto done;
        }
        case OE_SYS_write:
        {
            int fd = (int)arg1;
            const void* buf = (void*)arg2;
            size_t count = (size_t)arg3;

            ret = oe_write(fd, buf, count);
            goto done;
        }
        case OE_SYS_close:
        {
            int fd = (int)arg1;

            ret = oe_close(fd);
            goto done;
        }
        case OE_SYS_dup:
        {
            int fd = (int)arg1;

            ret = oe_dup(fd);
            goto done;
        }
        case OE_SYS_flock:
        {
            int fd = (int)arg1;
            int operation = (int)arg2;

            ret = oe_flock(fd, operation);
            goto done;
        }
        case OE_SYS_fsync:
        {
            const int fd = (int)arg1;

            ret = oe_fsync(fd);
            goto done;
        }
        case OE_SYS_fdatasync:
        {
            const int fd = (int)arg1;

            ret = oe_fdatasync(fd);
            goto done;
        }
#if defined(OE_SYS_dup2)
        case OE_SYS_dup2:
        {
            int oldfd = (int)arg1;
            int newfd = (int)arg2;

            ret = oe_dup2(oldfd, newfd);
            goto done;
        }
#endif
        case OE_SYS_dup3:
        {
            int oldfd = (int)arg1;
            int newfd = (int)arg2;
            int flags = (int)arg3;

            if (flags != 0)
            {
                oe_errno = OE_EINVAL;
                goto done;
            }

            ret = oe_dup2(oldfd, newfd);
            goto done;
        }
#if defined(OE_SYS_stat)
        case OE_SYS_stat:
        {
            const char* pathname = (const char*)arg1;
            struct oe_stat_t* buf = (struct oe_stat_t*)arg2;
            ret = oe_stat(pathname, buf);
            goto done;
        }
#endif
        case OE_SYS_newfstatat:
        {
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
            goto done;
        }
        case OE_SYS_fstat:
        {
            const int fd = (int)arg1;
            struct oe_stat_t* const buf = (struct oe_stat_t*)arg2;
            ret = oe_fstat(fd, buf);
            goto done;
        }
#if defined(OE_SYS_link)
        case OE_SYS_link:
        {
            const char* oldpath = (const char*)arg1;
            const char* newpath = (const char*)arg2;
            ret = oe_link(oldpath, newpath);
            goto done;
        }
#endif
        case OE_SYS_linkat:
        {
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
            goto done;
        }
#if defined(OE_SYS_unlink)
        case OE_SYS_unlink:
        {
            const char* pathname = (const char*)arg1;

            ret = oe_unlink(pathname);
            goto done;
        }
#endif
        case OE_SYS_unlinkat:
        {
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

            goto done;
        }
#if defined(OE_SYS_rename)
        case OE_SYS_rename:
        {
            const char* oldpath = (const char*)arg1;
            const char* newpath = (const char*)arg2;

            ret = oe_rename(oldpath, newpath);
            goto done;
        }
#endif
        case OE_SYS_renameat:
        {
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
            goto done;
        }
        case OE_SYS_truncate:
        {
            const char* path = (const char*)arg1;
            ssize_t length = (ssize_t)arg2;

            ret = oe_truncate(path, length);
            goto done;
        }
#if defined(OE_SYS_mkdir)
        case OE_SYS_mkdir:
        {
            const char* pathname = (const char*)arg1;
            uint32_t mode = (uint32_t)arg2;

            ret = oe_mkdir(pathname, mode);
            goto done;
        }
#endif
        case OE_SYS_mkdirat:
        {
            int dirfd = (int)arg1;
            const char* pathname = (const char*)arg2;
            uint32_t mode = (uint32_t)arg3;

            if (dirfd != OE_AT_FDCWD)
            {
                oe_errno = OE_EBADF;
                goto done;
            }

            ret = oe_mkdir(pathname, mode);
            goto done;
        }
#if defined(OE_SYS_rmdir)
        case OE_SYS_rmdir:
        {
            const char* pathname = (const char*)arg1;
            ret = oe_rmdir(pathname);
            goto done;
        }
#endif
#if defined(OE_SYS_access)
        case OE_SYS_access:
        {
            const char* pathname = (const char*)arg1;
            int mode = (int)arg2;

            ret = oe_access(pathname, mode);
            goto done;
        }
#endif
        case OE_SYS_faccessat:
        {
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
            goto done;
        }
        case OE_SYS_getdents64:
        {
            unsigned int fd = (unsigned int)arg1;
            struct oe_dirent* ent = (struct oe_dirent*)arg2;
            unsigned int count = (unsigned int)arg3;
            ret = oe_getdents64(fd, ent, count);
            goto done;
        }
        case OE_SYS_ioctl:
        {
            int fd = (int)arg1;
            unsigned long request = (unsigned long)arg2;
            long p1 = arg3;
            long p2 = arg4;
            long p3 = arg5;
            long p4 = arg6;

            ret = oe_ioctl(fd, request, p1, p2, p3, p4);
            goto done;
        }
        case OE_SYS_fcntl:
        {
            int fd = (int)arg1;
            int cmd = (int)arg2;
            uint64_t arg = (uint64_t)arg3;
            ret = oe_fcntl(fd, cmd, arg);
            goto done;
        }
        case OE_SYS_mount:
        {
            const char* source = (const char*)arg1;
            const char* target = (const char*)arg2;
            const char* fstype = (const char*)arg3;
            unsigned long flags = (unsigned long)arg4;
            void* data = (void*)arg5;

            ret = oe_mount(source, target, fstype, flags, data);
            goto done;
        }
        case OE_SYS_umount2:
        {
            const char* target = (const char*)arg1;
            int flags = (int)arg2;

            (void)flags;

            ret = oe_umount(target);
            goto done;
        }
        case OE_SYS_getcwd:
        {
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

            goto done;
        }
        case OE_SYS_chdir:
        {
            char* path = (char*)arg1;

            ret = oe_chdir(path);
            goto done;
        }
        case OE_SYS_socket:
        {
            int domain = (int)arg1;
            int type = (int)arg2;
            int protocol = (int)arg3;
            ret = oe_socket(domain, type, protocol);
            goto done;
        }
        case OE_SYS_connect:
        {
            int sd = (int)arg1;
            const struct oe_sockaddr* addr = (const struct oe_sockaddr*)arg2;
            oe_socklen_t addrlen = (oe_socklen_t)arg3;
            ret = oe_connect(sd, addr, addrlen);
            goto done;
        }
        case OE_SYS_setsockopt:
        {
            int sockfd = (int)arg1;
            int level = (int)arg2;
            int optname = (int)arg3;
            void* optval = (void*)arg4;
            oe_socklen_t optlen = (oe_socklen_t)arg5;
            ret = oe_setsockopt(sockfd, level, optname, optval, optlen);
            goto done;
        }
        case OE_SYS_getsockopt:
        {
            int sockfd = (int)arg1;
            int level = (int)arg2;
            int optname = (int)arg3;
            void* optval = (void*)arg4;
            oe_socklen_t* optlen = (oe_socklen_t*)arg5;
            ret = oe_getsockopt(sockfd, level, optname, optval, optlen);
            goto done;
        }
        case OE_SYS_getpeername:
        {
            int sockfd = (int)arg1;
            struct sockaddr* addr = (struct sockaddr*)arg2;
            oe_socklen_t* addrlen = (oe_socklen_t*)arg3;
            ret = oe_getpeername(sockfd, (struct oe_sockaddr*)addr, addrlen);
            goto done;
        }
        case OE_SYS_getsockname:
        {
            int sockfd = (int)arg1;
            struct sockaddr* addr = (struct sockaddr*)arg2;
            oe_socklen_t* addrlen = (oe_socklen_t*)arg3;
            ret = oe_getsockname(sockfd, (struct oe_sockaddr*)addr, addrlen);
            goto done;
        }
        case OE_SYS_bind:
        {
            int sockfd = (int)arg1;
            struct oe_sockaddr* addr = (struct oe_sockaddr*)arg2;
            oe_socklen_t addrlen = (oe_socklen_t)arg3;
            ret = oe_bind(sockfd, addr, addrlen);
            goto done;
        }
        case OE_SYS_listen:
        {
            int sockfd = (int)arg1;
            int backlog = (int)arg2;
            ret = oe_listen(sockfd, backlog);
            goto done;
        }
        case OE_SYS_accept:
        {
            int sockfd = (int)arg1;
            struct oe_sockaddr* addr = (struct oe_sockaddr*)arg2;
            oe_socklen_t* addrlen = (oe_socklen_t*)arg3;
            ret = oe_accept(sockfd, addr, addrlen);
            goto done;
        }
        case OE_SYS_sendto:
        {
            int sockfd = (int)arg1;
            const void* buf = (void*)arg2;
            size_t len = (size_t)arg3;
            int flags = (int)arg4;
            const struct oe_sockaddr* dest_add =
                (const struct oe_sockaddr*)arg5;
            oe_socklen_t addrlen = (oe_socklen_t)arg6;

            ret = oe_sendto(sockfd, buf, len, flags, dest_add, addrlen);
            goto done;
        }
        case OE_SYS_recvfrom:
        {
            int sockfd = (int)arg1;
            void* buf = (void*)arg2;
            size_t len = (size_t)arg3;
            int flags = (int)arg4;
            const struct oe_sockaddr* dest_add =
                (const struct oe_sockaddr*)arg5;
            oe_socklen_t* addrlen = (oe_socklen_t*)arg6;

            ret = oe_recvfrom(sockfd, buf, len, flags, dest_add, addrlen);
            goto done;
        }
        case OE_SYS_sendmsg:
        {
            int sockfd = (int)arg1;
            struct msghdr* buf = (struct msghdr*)arg2;
            int flags = (int)arg3;

            ret = oe_sendmsg(sockfd, (struct oe_msghdr*)buf, flags);
            goto done;
        }
        case OE_SYS_recvmsg:
        {
            int sockfd = (int)arg1;
            struct msghdr* buf = (struct msghdr*)arg2;
            int flags = (int)arg3;

            ret = oe_recvmsg(sockfd, (struct oe_msghdr*)buf, flags);
            goto done;
        }
        case OE_SYS_socketpair:
        {
            int domain = (int)arg1;
            int type = (int)arg2;
            int protocol = (int)arg3;
            int* sv = (int*)arg4;

            ret = oe_socketpair(domain, type, protocol, sv);
            goto done;
        }
        case OE_SYS_shutdown:
        {
            int sockfd = (int)arg1;
            int how = (int)arg2;
            ret = oe_shutdown(sockfd, how);
            goto done;
        }
        case OE_SYS_uname:
        {
            struct oe_utsname* buf = (struct oe_utsname*)arg1;
            ret = oe_uname(buf);
            goto done;
        }
#if defined(OE_SYS_select)
        case OE_SYS_select:
        {
            int nfds = (int)arg1;
            oe_fd_set* readfds = (oe_fd_set*)arg2;
            oe_fd_set* writefds = (oe_fd_set*)arg3;
            oe_fd_set* efds = (oe_fd_set*)arg4;
            struct oe_timeval* timeout = (struct oe_timeval*)arg5;
            ret = oe_select(nfds, readfds, writefds, efds, timeout);
            goto done;
        }
#endif
        case OE_SYS_pselect6:
        {
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

            ret = oe_select(nfds, readfds, writefds, exceptfds, tv);
            goto done;
        }
#if defined(OE_SYS_poll)
        case OE_SYS_poll:
        {
            struct oe_pollfd* fds = (struct oe_pollfd*)arg1;
            oe_nfds_t nfds = (oe_nfds_t)arg2;
            int millis = (int)arg3;
            ret = oe_poll(fds, nfds, millis);
            goto done;
        }
#endif
        case OE_SYS_ppoll:
        {
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
            goto done;
        }
#if defined(OE_SYS_epoll_create)
        case OE_SYS_epoll_create:
        {
            int size = (int)arg1;
            ret = oe_epoll_create(size);
            goto done;
        }
#endif
        case OE_SYS_epoll_create1:
        {
            int flags = (int)arg1;
            ret = oe_epoll_create1(flags);
            goto done;
        }
#if defined(OE_SYS_epoll_wait)
        case OE_SYS_epoll_wait:
        {
            int epfd = (int)arg1;
            struct oe_epoll_event* events = (struct oe_epoll_event*)arg2;
            int maxevents = (int)arg3;
            int timeout = (int)arg4;
            ret = oe_epoll_wait(epfd, events, maxevents, timeout);
            goto done;
        }
#endif
        case OE_SYS_epoll_pwait:
        {
            int epfd = (int)arg1;
            struct oe_epoll_event* events = (struct oe_epoll_event*)arg2;
            int maxevents = (int)arg3;
            int timeout = (int)arg4;
            const oe_sigset_t* sigmask = (const oe_sigset_t*)arg5;
            ret = oe_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
            goto done;
        }
        case OE_SYS_epoll_ctl:
        {
            int epfd = (int)arg1;
            int op = (int)arg2;
            int fd = (int)arg3;
            struct oe_epoll_event* event = (struct oe_epoll_event*)arg4;
            ret = oe_epoll_ctl(epfd, op, fd, event);
            goto done;
        }
        case OE_SYS_exit_group:
        {
            ret = 0;
            goto done;
        }
        case OE_SYS_exit:
        {
            int status = (int)arg1;
            oe_exit(status);
            goto done;
        }
        case OE_SYS_getpid:
        {
            ret = (long)oe_getpid();
            goto done;
        }
        case OE_SYS_getuid:
        {
            ret = (long)oe_getuid();
            goto done;
        }
        case OE_SYS_geteuid:
        {
            ret = (long)oe_geteuid();
            goto done;
        }
        case OE_SYS_getgid:
        {
            ret = (long)oe_getgid();
            goto done;
        }
        case OE_SYS_getpgid:
        {
            int pid = (int)arg1;
            ret = (long)oe_getpgid(pid);
            goto done;
        }
        case OE_SYS_getgroups:
        {
            int size = (int)arg1;
            oe_gid_t* list = (oe_gid_t*)arg2;
            ret = (long)oe_getgroups(size, list);
            goto done;
        }
        case OE_SYS_getegid:
        {
            ret = (long)oe_getegid();
            goto done;
        }
        case OE_SYS_getppid:
        {
            ret = (long)oe_getppid();
            goto done;
        }
#if defined(OE_SYS_getpgrp)
        case OE_SYS_getpgrp:
        {
            ret = (long)oe_getpgrp();
            goto done;
        }
#endif
        case OE_SYS_nanosleep:
        {
            struct oe_timespec* req = (struct oe_timespec*)arg1;
            struct oe_timespec* rem = (struct oe_timespec*)arg2;
            ret = (long)oe_nanosleep(req, rem);
            goto done;
        }
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
