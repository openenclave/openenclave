// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

typedef __int64 oe_oe_off_t;

#include <windows.h>
#include <io.h>
#include <stdint.h>
/* ATTN: please put what 4005 is for here. */

#pragma warning(disable : 4005)

/* warning C4716: must return a value */
#pragma warning(disable : 4716)

#include "posix_u.h"

/*
**==============================================================================
**
** Local definitions.
**
**==============================================================================
*/

OE_INLINE void _set_err(int* err, int num)
{
    if (err)
        *err = num;
}

OE_INLINE void _clear_err(int* err)
{
    errno = 0;

    if (err)
        *err = 0;
}

static void _panic(const char* file, unsigned int line, const char* function)
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

oe_host_fd_t oe_posix_open_ocall(
    const char* pathname,
    int flags,
    oe_mode_t mode,
    int* err)
{
    PANIC;
}

ssize_t oe_posix_read_ocall(oe_host_fd_t fd, void* buf, size_t count, int* err)
{
    /* ATTN: casting 64-bit fd to 32-bit fd */
    ssize_t ret = _read((int)fd, buf, (uint32_t)count);

    if (ret == -1 && err)
        *err = errno;

    return ret;
}

ssize_t oe_posix_write_ocall(
    oe_host_fd_t fd,
    const void* buf,
    size_t count,
    int* err)
{
    /* ATTN: casting 64-bit fd to 32-bit fd */
    ssize_t ret = _write((int)fd, buf, (uint32_t)count);

    if (ret == -1 && err)
        *err = errno;

    return ret;
}

oe_off_t oe_posix_lseek_ocall(oe_host_fd_t fd, oe_off_t offset, int whence, int* err)
{
    PANIC;
}

int oe_posix_close_ocall(oe_host_fd_t fd, int* err)
{
    PANIC;
}

oe_host_fd_t oe_posix_dup_ocall(oe_host_fd_t oldfd, int* err)
{
    PANIC;
}

uint64_t oe_posix_opendir_ocall(const char* name, int* err)
{
    PANIC;
}

int oe_posix_readdir_ocall(
    uint64_t dirp,
    uint64_t* d_ino,
    int64_t* d_off,
    uint16_t* d_reclen,
    uint8_t* d_type,
    char* d_name,
    size_t d_namelen,
    int* err)
{
    PANIC;
}

void oe_posix_rewinddir_ocall(uint64_t dirp)
{
}

int oe_posix_closedir_ocall(uint64_t dirp, int* err)
{
    PANIC;
}

int oe_posix_stat_ocall(const char* pathname, struct oe_stat* buf, int* err)
{
    PANIC;
}

int oe_posix_access_ocall(const char* pathname, int mode, int* err)
{
    PANIC;
}

int oe_posix_link_ocall(const char* oldpath, const char* newpath, int* err)
{
    PANIC;
}

int oe_posix_unlink_ocall(const char* pathname, int* err)
{
    PANIC;
}

int oe_posix_rename_ocall(const char* oldpath, const char* newpath, int* err)
{
    PANIC;
}

int oe_posix_truncate_ocall(const char* path, oe_off_t length, int* err)
{
    PANIC;
}

int oe_posix_mkdir_ocall(const char* pathname, oe_mode_t mode, int* err)
{
    PANIC;
}

int oe_posix_rmdir_ocall(const char* pathname, int* err)
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

oe_host_fd_t oe_posix_socket_ocall(int domain, int type, int protocol, int* err)
{
    PANIC;
}

int oe_posix_socketpair_ocall(
    int domain,
    int type,
    int protocol,
    oe_host_fd_t sv_out[2],
    int* err)
{
    PANIC;
}

int oe_posix_connect_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen,
    int* err)
{
    PANIC;
}

oe_host_fd_t oe_posix_accept_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out,
    int* err)
{
    PANIC;
}

int oe_posix_bind_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen,
    int* err)
{
    PANIC;
}

int oe_posix_listen_ocall(oe_host_fd_t sockfd, int backlog, int* err)
{
    PANIC;
}

ssize_t oe_posix_recvmsg_ocall(
    oe_host_fd_t sockfd,
    void* msg_name,
    oe_socklen_t msg_namelen,
    oe_socklen_t* msg_namelen_out,
    void* msg_buf,
    size_t msg_buflen,
    void* msg_control,
    size_t msg_controllen,
    size_t* msg_controllen_out,
    int flags,
    int* err)
{
    PANIC;
}

ssize_t oe_posix_sendmsg_ocall(
    oe_host_fd_t sockfd,
    const void* msg_name,
    oe_socklen_t msg_namelen,
    const void* msg_buf,
    size_t msg_buflen,
    const void* msg_control,
    size_t msg_controllen,
    int flags,
    int* err)
{
    PANIC;
}

ssize_t oe_posix_recv_ocall(
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags,
    int* err)
{
    PANIC;
}

ssize_t oe_posix_recvfrom_ocall(
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags,
    struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out,
    int* err)
{
    PANIC;
}

ssize_t oe_posix_send_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags,
    int* err)
{
    PANIC;
}

ssize_t oe_posix_sendto_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen,
    int* err)
{
    PANIC;
}

int oe_posix_shutdown_ocall(oe_host_fd_t sockfd, int how, int* err)
{
    PANIC;
}

int oe_posix_fcntl_ocall(oe_host_fd_t fd, int cmd, uint64_t arg, int* err)
{
    PANIC;
}

int oe_posix_setsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    const void* optval,
    oe_socklen_t optlen,
    int* err)
{
    PANIC;
}

int oe_posix_getsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    void* optval,
    oe_socklen_t optlen_in,
    oe_socklen_t* optlen_out,
    int* err)
{
    PANIC;
}

int oe_posix_getsockname_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out,
    int* err)
{
    PANIC;
}

int oe_posix_getpeername_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out,
    int* err)
{
    PANIC;
}

int oe_posix_shutdown_sockets_device_ocall(oe_host_fd_t sockfd, int* err)
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

int oe_posix_kill_ocall(int pid, int signum, int* err)
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

uint64_t oe_posix_getaddrinfo_open_ocall(
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    int* err)
{
    PANIC;
}

int oe_posix_getaddrinfo_read_ocall(
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
    char* ai_canonname,
    int* err)
{
    PANIC;
}

int oe_posix_getaddrinfo_close_ocall(uint64_t handle_, int* err)
{
    PANIC;
}

int oe_posix_getnameinfo_ocall(
    const struct oe_sockaddr* sa,
    oe_socklen_t salen,
    char* host,
    oe_socklen_t hostlen,
    char* serv,
    oe_socklen_t servlen,
    int flags,
    int* err)
{
    PANIC;
}

int oe_posix_shutdown_resolver_device_ocall(int* err)
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

oe_host_fd_t oe_posix_epoll_create1_ocall(int flags, int* err)
{
    PANIC;
}

int oe_posix_epoll_wait_async_ocall(
    int64_t enclaveid,
    oe_host_fd_t epfd,
    size_t maxevents,
    int* err)
{
    PANIC;
}

int oe_posix_epoll_ctl_add_ocall(
    oe_host_fd_t epfd,
    oe_host_fd_t fd,
    unsigned int event_mask,
    int list_idx,
    int epoll_enclave_fd,
    int* err)
{
    PANIC;
}

int oe_posix_epoll_ctl_del_ocall(oe_host_fd_t epfd, oe_host_fd_t fd, int* err)
{
    PANIC;
}

int oe_posix_epoll_ctl_mod_ocall(
    oe_host_fd_t epfd,
    oe_host_fd_t fd,
    unsigned int event_mask,
    int list_idx,
    int enclave_fd,
    int* err)
{
    PANIC;
}

int oe_posix_epoll_close_ocall(oe_host_fd_t fd, int* err)
{
    PANIC;
}

int oe_posix_shutdown_polling_device_ocall(oe_host_fd_t fd, int* err)
{
    PANIC;
}

int oe_posix_epoll_poll_ocall(
    int64_t enclaveid,
    oe_host_fd_t epfd,
    struct oe_pollfd* fds,
    size_t nfds,
    int timeout,
    int* err)
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

int oe_posix_getpid(void)
{
    PANIC;
}

int oe_posix_getppid(void)
{
    PANIC;
}

int oe_posix_getpgrp(void)
{
    PANIC;
}

unsigned int oe_posix_getuid(void)
{
    PANIC;
}

unsigned int oe_posix_geteuid(void)
{
    PANIC;
}

unsigned int oe_posix_getgid(void)
{
    PANIC;
}

unsigned int oe_posix_getegid(void)
{
    PANIC;
}

int oe_posix_getpgid(int pid, int* err)
{
    PANIC;
}

int oe_posix_getgroups(size_t size, unsigned int* list, int* err)
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

int oe_posix_uname_ocall(struct oe_utsname* buf, int* err)
{
    PANIC;
}
