// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
**==============================================================================
**
** windows/syscall.c:
**
**     This file implements SYSCALL OCALLs for Windows. Most of these are stubs
**     which are still under development.
**
**==============================================================================
*/

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <direct.h>
#include <io.h>
#include <stdint.h>
#include <sys/stat.h>

// clang-format off
#include <windows.h>
// clang-format on

#include <openenclave/corelibc/errno.h>
#include <openenclave/internal/syscall/sys/epoll.h>
#include <openenclave/internal/syscall/fcntl.h>
#include <openenclave/internal/syscall/dirent.h>
#include <openenclave/internal/syscall/unistd.h>
#include "../hostthread.h"
#include "syscall_u.h"

/*
**==============================================================================
**
** PANIC -- remove this when no longer needed.
**
**==============================================================================
*/

__declspec(noreturn) static void _panic(
    const char* file,
    unsigned int line,
    const char* function)
{
    fprintf(stderr, "%s(%u): %s(): panic\n", file, line, function);
    abort();
}

#define PANIC _panic(__FILE__, __LINE__, __FUNCTION__)

/*
**==============================================================================
**
** File and directory I/O:
**
**==============================================================================
*/

/* Mask to extract open() access mode flags: O_RDONLY, O_WRONLY, O_RDWR. */
#define OPEN_ACCESS_MODE_MASK 0x00000003

oe_host_fd_t oe_syscall_open_ocall(
    const char* pathname,
    int flags,
    oe_mode_t mode)
{
    oe_host_fd_t ret = -1;

    if (strcmp(pathname, "/dev/stdin") == 0)
    {
        if ((flags & OPEN_ACCESS_MODE_MASK) != OE_O_RDONLY)
        {
            _set_errno(OE_EINVAL);
            goto done;
        }

        ret = _dup(OE_STDIN_FILENO);
        goto done;
    }
    else if (strcmp(pathname, "/dev/stdout") == 0)
    {
        if ((flags & OPEN_ACCESS_MODE_MASK) != OE_O_WRONLY)
        {
            _set_errno(OE_EINVAL);
            goto done;
        }

        ret = _dup(OE_STDOUT_FILENO);
        goto done;
    }
    else if (strcmp(pathname, "/dev/stderr") == 0)
    {
        if ((flags & OPEN_ACCESS_MODE_MASK) != OE_O_WRONLY)
        {
            _set_errno(OE_EINVAL);
            goto done;
        }

        ret = _dup(OE_STDERR_FILENO);
        goto done;
    }
    else
    {
        /* Opening of files not supported on Windows yet. */
        PANIC;
    }

done:

    return ret;
}

ssize_t oe_syscall_read_ocall(oe_host_fd_t fd, void* buf, size_t count)
{
    return _read(fd, buf, count);
}

ssize_t oe_syscall_write_ocall(oe_host_fd_t fd, const void* buf, size_t count)
{
    return _write(fd, buf, count);
}

ssize_t oe_syscall_readv_ocall(
    oe_host_fd_t fd,
    void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    struct oe_iovec* iov = (struct oe_iovec*)iov_buf;
    ssize_t ret = -1;
    ssize_t size_read;

    errno = 0;

    if ((!iov && iovcnt) || iovcnt < 0 || iovcnt > OE_IOV_MAX)
    {
        errno = EINVAL;
        goto done;
    }

    /* Handle zero data case. */
    if (!iov || iovcnt == 0)
    {
        ret = 0;
        goto done;
    }

    {
        void* buf;
        size_t count;

        buf = &iov[iovcnt];
        count = iov_buf_size - ((size_t)iovcnt * sizeof(struct oe_iovec));

        size_read = oe_syscall_read_ocall(fd, buf, count);
    }

    ret = size_read;

done:
    return ret;
}

ssize_t oe_syscall_writev_ocall(
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    ssize_t ret = -1;
    ssize_t size_written;
    struct oe_iovec* iov = (struct oe_iovec*)iov_buf;

    errno = 0;

    if ((!iov && iovcnt) || iovcnt < 0 || iovcnt > OE_IOV_MAX)
    {
        errno = EINVAL;
        goto done;
    }

    /* Handle zero data case. */
    if (!iov || iovcnt == 0)
    {
        ret = 0;
        goto done;
    }

    {
        const void* buf;
        size_t count;

        buf = &iov[iovcnt];
        count = iov_buf_size - ((size_t)iovcnt * sizeof(struct oe_iovec));

        size_written = oe_syscall_write_ocall(fd, buf, count);
    }

    ret = size_written;

done:
    return ret;
}

oe_off_t oe_syscall_lseek_ocall(oe_host_fd_t fd, oe_off_t offset, int whence)
{
    PANIC;
}

int oe_syscall_close_ocall(oe_host_fd_t fd)
{
    return _close(fd);
}

oe_host_fd_t oe_syscall_dup_ocall(oe_host_fd_t oldfd)
{
    PANIC;
}

uint64_t oe_syscall_opendir_ocall(const char* pathname)
{
    PANIC;
}

int oe_syscall_readdir_ocall(uint64_t dirp, struct oe_dirent* entry)
{
    PANIC;
}

void oe_syscall_rewinddir_ocall(uint64_t dirp)
{
    PANIC;
}

int oe_syscall_closedir_ocall(uint64_t dirp)
{
    PANIC;
}

int oe_syscall_stat_ocall(const char* pathname, struct oe_stat* buf)
{
    PANIC;
}

int oe_syscall_access_ocall(const char* pathname, int mode)
{
    PANIC;
}

int oe_syscall_link_ocall(const char* oldpath, const char* newpath)
{
    PANIC;
}

int oe_syscall_unlink_ocall(const char* pathname)
{
    PANIC;
}

int oe_syscall_rename_ocall(const char* oldpath, const char* newpath)
{
    PANIC;
}

int oe_syscall_truncate_ocall(const char* pathname, oe_off_t length)
{
    PANIC;
}

int oe_syscall_mkdir_ocall(const char* pathname, oe_mode_t mode)
{
    PANIC;
}

int oe_syscall_rmdir_ocall(const char* pathname)
{
    PANIC;
}

/*
**==============================================================================
**
** Socket I/O:
**
**==============================================================================
*/

oe_host_fd_t oe_syscall_socket_ocall(int domain, int type, int protocol)
{
    PANIC;
}

int oe_syscall_socketpair_ocall(
    int domain,
    int type,
    int protocol,
    oe_host_fd_t sv_out[2])
{
    PANIC;
}

int oe_syscall_connect_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    PANIC;
}

oe_host_fd_t oe_syscall_accept_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    PANIC;
}

int oe_syscall_bind_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    PANIC;
}

int oe_syscall_listen_ocall(oe_host_fd_t sockfd, int backlog)
{
    PANIC;
}

ssize_t oe_syscall_recvmsg_ocall(
    oe_host_fd_t sockfd,
    void* msg_name,
    oe_socklen_t msg_namelen,
    oe_socklen_t* msg_namelen_out,
    void* msg_iov_buf,
    size_t msg_iovlen,
    size_t msg_iov_buf_size,
    void* msg_control,
    size_t msg_controllen,
    size_t* msg_controllen_out,
    int flags)
{
    PANIC;
}

ssize_t oe_syscall_sendmsg_ocall(
    oe_host_fd_t sockfd,
    const void* msg_name,
    oe_socklen_t msg_namelen,
    void* msg_iov_buf,
    size_t msg_iovlen,
    size_t msg_iov_buf_size,
    const void* msg_control,
    size_t msg_controllen,
    int flags)
{
    PANIC;
}

ssize_t oe_syscall_recv_ocall(
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags)
{
    PANIC;
}

ssize_t oe_syscall_recvfrom_ocall(
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags,
    struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    PANIC;
}

ssize_t oe_syscall_send_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags)
{
    PANIC;
}

ssize_t oe_syscall_sendto_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen)
{
    PANIC;
}

ssize_t oe_syscall_recvv_ocall(
    oe_host_fd_t fd,
    void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    PANIC;
}

ssize_t oe_syscall_sendv_ocall(
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    PANIC;
}

int oe_syscall_shutdown_ocall(oe_host_fd_t sockfd, int how)
{
    PANIC;
}

int oe_syscall_close_socket_ocall(oe_host_fd_t sockfd)
{
    PANIC;
}

int oe_syscall_fcntl_ocall(oe_host_fd_t fd, int cmd, uint64_t arg)
{
    PANIC;
}

#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414

int oe_syscall_ioctl_ocall(oe_host_fd_t fd, uint64_t request, uint64_t arg)
{
    errno = 0;

    // We don't support any ioctls right now as we will have to translate the
    // codes from the enclave to be the equivelent for windows. But... no such
    // codes are currently being used So we panic to highlight the problem line
    // of code. In this way, we can see what ioctls are needed

    switch (request)
    {
        case TIOCGWINSZ:
        case TIOCSWINSZ:
            _set_errno(OE_ENOTTY);
            break;
        default:
            _set_errno(OE_EINVAL);
            break;
    }

    return -1;
}

int oe_syscall_setsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    const void* optval,
    oe_socklen_t optlen)
{
    PANIC;
}

int oe_syscall_getsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    void* optval,
    oe_socklen_t optlen_in,
    oe_socklen_t* optlen_out)
{
    PANIC;
}

int oe_syscall_getsockname_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    PANIC;
}

int oe_syscall_getpeername_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    PANIC;
}

int oe_syscall_shutdown_sockets_device_ocall(oe_host_fd_t sockfd)
{
    PANIC;
}

/*
**==============================================================================
**
** Signals:
**
**==============================================================================
*/

int oe_syscall_kill_ocall(int pid, int signum)
{
    PANIC;
}

/*
**==============================================================================
**
** Resolver:
**
**==============================================================================
*/

int oe_syscall_getaddrinfo_open_ocall(
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    uint64_t* handle_out)
{
    PANIC;
}

int oe_syscall_getaddrinfo_read_ocall(
    uint64_t handle_,
    int* ai_flags,
    int* ai_family,
    int* ai_socktype,
    int* ai_protocol,
    oe_socklen_t ai_addrlen_in,
    oe_socklen_t* ai_addrlen,
    struct oe_sockaddr* ai_addr,
    size_t ai_canonnamelen_in,
    size_t* ai_canonnamelen,
    char* ai_canonname)
{
    PANIC;
}

int oe_syscall_getaddrinfo_close_ocall(uint64_t handle_)
{
    PANIC;
}

int oe_syscall_getnameinfo_ocall(
    const struct oe_sockaddr* sa,
    oe_socklen_t salen,
    char* host,
    oe_socklen_t hostlen,
    char* serv,
    oe_socklen_t servlen,
    int flags)
{
    PANIC;
}

/*
**==============================================================================
**
** Polling:
**
**==============================================================================
*/

oe_host_fd_t oe_syscall_epoll_create1_ocall(int flags)
{
    PANIC;
}

int oe_syscall_epoll_wait_ocall(
    int64_t epfd,
    struct oe_epoll_event* events,
    unsigned int maxevents,
    int timeout)
{
    PANIC;
}

int oe_syscall_epoll_wake_ocall(void)
{
    PANIC;
}

int oe_syscall_epoll_ctl_ocall(
    int64_t epfd,
    int op,
    int64_t fd,
    struct oe_epoll_event* event)
{
    PANIC;
}

int oe_syscall_epoll_close_ocall(oe_host_fd_t epfd)
{
    PANIC;
}

int oe_syscall_shutdown_polling_device_ocall(oe_host_fd_t fd)
{
    PANIC;
}

/*
**==============================================================================
**
** poll()
**
**==============================================================================
*/

int oe_syscall_poll_ocall(
    struct oe_host_pollfd* host_fds,
    oe_nfds_t nfds,
    int timeout)
{
    PANIC;
}

/*
**==============================================================================
**
** uid, gid, pid, and groups:
**
**==============================================================================
*/

int oe_syscall_getpid_ocall(void)
{
    PANIC;
}

int oe_syscall_getppid_ocall(void)
{
    PANIC;
}

int oe_syscall_getpgrp_ocall(void)
{
    PANIC;
}

unsigned int oe_syscall_getuid_ocall(void)
{
    PANIC;
}

unsigned int oe_syscall_geteuid_ocall(void)
{
    PANIC;
}

unsigned int oe_syscall_getgid_ocall(void)
{
    PANIC;
}

unsigned int oe_syscall_getegid_ocall(void)
{
    PANIC;
}

int oe_syscall_getpgid_ocall(int pid)
{
    PANIC;
}

int oe_syscall_getgroups_ocall(size_t size, unsigned int* list)
{
    PANIC;
}

/*
**==============================================================================
**
** uname():
**
**==============================================================================
*/

int oe_syscall_uname_ocall(struct oe_utsname* buf)
{
    PANIC;
}
