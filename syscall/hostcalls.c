// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "syscall_t.h"

/*
 * This file implements the default implementations of syscall-related
 * system ocall wrappers. Each implementation is simply an empty function
 * that returns OE_UNSUPPORTED. If a user does not opt-into these ocalls
 * (via importing the edls), the linker will pick the default implementions
 * (which are weak). If the user opts-into any of the ocalls, the linker will
 * pick the oeedger8r-generated wrapper of the corresponding ocall (which
 * is strong) instead.
 *
 * Note that we need to make the default implementations weak to support
 * selective ocall import. The reason for this is that if the linker picks
 * one of the symbols from an object file, it also pulls the rest of the
 * symbols in the same object file. This behavior causes multiple definition
 * errors when the user wants to selectively import ocalls if the default
 * implementations are strong. For example, the user imports one ocall from
 * epoll.edl. The linker firstly picks the oeedger8r-generated implementation
 * of the ocall. However, when the linker looks up the default implementations
 * of the non-imported ocalls in this object file (hostcalls.o), it also pulls
 * the default implementation of the imported ocall. Because both the default
 * and the oeedger8r-generated implementations are strong, the linker raises the
 * error.
 */

#if !defined(OE_USE_BUILTIN_EDL)

/*
**==============================================================================
**
** epoll.edl
**
**==============================================================================
*/

/**
 * Declare the prototypes of the following functions to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_syscall_epoll_create1_ocall(oe_host_fd_t* _retval, int flags);
oe_result_t _oe_syscall_epoll_wait_ocall(
    int* _retval,
    int64_t epfd,
    struct oe_epoll_event* events,
    unsigned int maxevents,
    int timeout);
oe_result_t _oe_syscall_epoll_wake_ocall(int* _retval);
oe_result_t _oe_syscall_epoll_ctl_ocall(
    int* _retval,
    int64_t epfd,
    int op,
    int64_t fd,
    struct oe_epoll_event* event);
oe_result_t _oe_syscall_epoll_close_ocall(int* _retval, oe_host_fd_t epfd);

/**
 * Implement the functions and make them as the weak aliases of
 * the public ocall wrappers.
 */
oe_result_t _oe_syscall_epoll_create1_ocall(oe_host_fd_t* _retval, int flags)
{
    OE_UNUSED(_retval);
    OE_UNUSED(flags);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_epoll_create1_ocall, oe_syscall_epoll_create1_ocall);

oe_result_t _oe_syscall_epoll_wait_ocall(
    int* _retval,
    int64_t epfd,
    struct oe_epoll_event* events,
    unsigned int maxevents,
    int timeout)
{
    OE_UNUSED(_retval);
    OE_UNUSED(epfd);
    OE_UNUSED(events);
    OE_UNUSED(maxevents);
    OE_UNUSED(timeout);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_epoll_wait_ocall, oe_syscall_epoll_wait_ocall);

oe_result_t _oe_syscall_epoll_wake_ocall(int* _retval)
{
    OE_UNUSED(_retval);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_epoll_wake_ocall, oe_syscall_epoll_wake_ocall);

oe_result_t _oe_syscall_epoll_ctl_ocall(
    int* _retval,
    int64_t epfd,
    int op,
    int64_t fd,
    struct oe_epoll_event* event)
{
    OE_UNUSED(_retval);
    OE_UNUSED(epfd);
    OE_UNUSED(op);
    OE_UNUSED(fd);
    OE_UNUSED(event);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_epoll_ctl_ocall, oe_syscall_epoll_ctl_ocall);

oe_result_t _oe_syscall_epoll_close_ocall(int* _retval, oe_host_fd_t epfd)
{
    OE_UNUSED(_retval);
    OE_UNUSED(epfd);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_epoll_close_ocall, oe_syscall_epoll_close_ocall);

/*
**==============================================================================
**
** fcntl.edl
**
**==============================================================================
*/

/**
 * Declare the prototypes of the following functions to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_syscall_open_ocall(
    oe_host_fd_t* _retval,
    const char* pathname,
    int flags,
    oe_mode_t mode);
oe_result_t _oe_syscall_read_ocall(
    ssize_t* _retval,
    oe_host_fd_t fd,
    void* buf,
    size_t count);
oe_result_t _oe_syscall_write_ocall(
    ssize_t* _retval,
    oe_host_fd_t fd,
    const void* buf,
    size_t count);
oe_result_t _oe_syscall_readv_ocall(
    ssize_t* _retval,
    oe_host_fd_t fd,
    void* iov_buf,
    int iovcnt,
    size_t iov_buf_size);
oe_result_t _oe_syscall_writev_ocall(
    ssize_t* _retval,
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size);
oe_result_t _oe_syscall_lseek_ocall(
    oe_off_t* _retval,
    oe_host_fd_t fd,
    oe_off_t offset,
    int whence);
oe_result_t _oe_syscall_pread_ocall(
    ssize_t* _retval,
    oe_host_fd_t fd,
    void* buf,
    size_t count,
    oe_off_t offset);
oe_result_t _oe_syscall_pwrite_ocall(
    ssize_t* _retval,
    oe_host_fd_t fd,
    const void* buf,
    size_t count,
    oe_off_t offset);
oe_result_t _oe_syscall_close_ocall(int* _retval, oe_host_fd_t fd);
oe_result_t _oe_syscall_dup_ocall(oe_host_fd_t* _retval, oe_host_fd_t oldfd);
oe_result_t _oe_syscall_opendir_ocall(uint64_t* _retval, const char* name);
oe_result_t _oe_syscall_readdir_ocall(
    int* _retval,
    uint64_t dirp,
    struct oe_dirent* entry);
oe_result_t _oe_syscall_rewinddir_ocall(uint64_t dirp);
oe_result_t _oe_syscall_closedir_ocall(int* _retval, uint64_t dirp);
oe_result_t _oe_syscall_stat_ocall(
    int* _retval,
    const char* pathname,
    struct oe_stat_t* buf);
oe_result_t _oe_syscall_access_ocall(
    int* _retval,
    const char* pathname,
    int mode);
oe_result_t _oe_syscall_link_ocall(
    int* _retval,
    const char* oldpath,
    const char* newpath);
oe_result_t _oe_syscall_unlink_ocall(int* _retval, const char* pathname);
oe_result_t _oe_syscall_rename_ocall(
    int* _retval,
    const char* oldpath,
    const char* newpath);
oe_result_t _oe_syscall_truncate_ocall(
    int* _retval,
    const char* path,
    oe_off_t length);
oe_result_t _oe_syscall_mkdir_ocall(
    int* _retval,
    const char* pathname,
    oe_mode_t mode);
oe_result_t _oe_syscall_rmdir_ocall(int* _retval, const char* pathname);
oe_result_t _oe_syscall_fcntl_ocall(
    int* _retval,
    oe_host_fd_t fd,
    int cmd,
    uint64_t arg,
    uint64_t argsize,
    void* argout);

/**
 * Implement the functions and make them as the weak aliases of
 * the public ocall wrappers.
 */
oe_result_t _oe_syscall_open_ocall(
    oe_host_fd_t* _retval,
    const char* pathname,
    int flags,
    oe_mode_t mode)
{
    OE_UNUSED(_retval);
    OE_UNUSED(pathname);
    OE_UNUSED(flags);
    OE_UNUSED(mode);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_open_ocall, oe_syscall_open_ocall);

oe_result_t _oe_syscall_read_ocall(
    ssize_t* _retval,
    oe_host_fd_t fd,
    void* buf,
    size_t count)
{
    OE_UNUSED(_retval);
    OE_UNUSED(fd);
    OE_UNUSED(buf);
    OE_UNUSED(count);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_read_ocall, oe_syscall_read_ocall);

oe_result_t _oe_syscall_write_ocall(
    ssize_t* _retval,
    oe_host_fd_t fd,
    const void* buf,
    size_t count)
{
    OE_UNUSED(_retval);
    OE_UNUSED(fd);
    OE_UNUSED(buf);
    OE_UNUSED(count);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_write_ocall, oe_syscall_write_ocall);

oe_result_t _oe_syscall_readv_ocall(
    ssize_t* _retval,
    oe_host_fd_t fd,
    void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    OE_UNUSED(_retval);
    OE_UNUSED(fd);
    OE_UNUSED(iov_buf);
    OE_UNUSED(iovcnt);
    OE_UNUSED(iov_buf_size);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_readv_ocall, oe_syscall_readv_ocall);

oe_result_t _oe_syscall_writev_ocall(
    ssize_t* _retval,
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    OE_UNUSED(_retval);
    OE_UNUSED(fd);
    OE_UNUSED(iov_buf);
    OE_UNUSED(iovcnt);
    OE_UNUSED(iov_buf_size);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_writev_ocall, oe_syscall_writev_ocall);

oe_result_t _oe_syscall_lseek_ocall(
    oe_off_t* _retval,
    oe_host_fd_t fd,
    oe_off_t offset,
    int whence)
{
    OE_UNUSED(_retval);
    OE_UNUSED(fd);
    OE_UNUSED(offset);
    OE_UNUSED(whence);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_lseek_ocall, oe_syscall_lseek_ocall);

oe_result_t _oe_syscall_pread_ocall(
    ssize_t* _retval,
    oe_host_fd_t fd,
    void* buf,
    size_t count,
    oe_off_t offset)
{
    OE_UNUSED(_retval);
    OE_UNUSED(fd);
    OE_UNUSED(buf);
    OE_UNUSED(count);
    OE_UNUSED(offset);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_pread_ocall, oe_syscall_pread_ocall);

oe_result_t _oe_syscall_pwrite_ocall(
    ssize_t* _retval,
    oe_host_fd_t fd,
    const void* buf,
    size_t count,
    oe_off_t offset)
{
    OE_UNUSED(_retval);
    OE_UNUSED(fd);
    OE_UNUSED(buf);
    OE_UNUSED(count);
    OE_UNUSED(offset);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_pwrite_ocall, oe_syscall_pwrite_ocall);

oe_result_t _oe_syscall_close_ocall(int* _retval, oe_host_fd_t fd)
{
    OE_UNUSED(_retval);
    OE_UNUSED(fd);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_close_ocall, oe_syscall_close_ocall);

oe_result_t _oe_syscall_flock_ocall(
    int* _retval,
    oe_host_fd_t fd,
    int operation)
{
    OE_UNUSED(_retval);
    OE_UNUSED(fd);
    OE_UNUSED(operation);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_flock_ocall, oe_syscall_flock_ocall);

oe_result_t _oe_syscall_dup_ocall(oe_host_fd_t* _retval, oe_host_fd_t oldfd)
{
    OE_UNUSED(_retval);
    OE_UNUSED(oldfd);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_dup_ocall, oe_syscall_dup_ocall);

oe_result_t _oe_syscall_opendir_ocall(uint64_t* _retval, const char* name)
{
    OE_UNUSED(_retval);
    OE_UNUSED(name);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_opendir_ocall, oe_syscall_opendir_ocall);

oe_result_t _oe_syscall_readdir_ocall(
    int* _retval,
    uint64_t dirp,
    struct oe_dirent* entry)
{
    OE_UNUSED(_retval);
    OE_UNUSED(dirp);
    OE_UNUSED(entry);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_readdir_ocall, oe_syscall_readdir_ocall);

oe_result_t _oe_syscall_rewinddir_ocall(uint64_t dirp)
{
    OE_UNUSED(dirp);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_rewinddir_ocall, oe_syscall_rewinddir_ocall);

oe_result_t _oe_syscall_closedir_ocall(int* _retval, uint64_t dirp)
{
    OE_UNUSED(_retval);
    OE_UNUSED(dirp);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_closedir_ocall, oe_syscall_closedir_ocall);

oe_result_t _oe_syscall_stat_ocall(
    int* _retval,
    const char* pathname,
    struct oe_stat_t* buf)
{
    OE_UNUSED(_retval);
    OE_UNUSED(pathname);
    OE_UNUSED(buf);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_stat_ocall, oe_syscall_stat_ocall);

oe_result_t _oe_syscall_access_ocall(
    int* _retval,
    const char* pathname,
    int mode)
{
    OE_UNUSED(_retval);
    OE_UNUSED(pathname);
    OE_UNUSED(mode);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_access_ocall, oe_syscall_access_ocall);

oe_result_t _oe_syscall_link_ocall(
    int* _retval,
    const char* oldpath,
    const char* newpath)
{
    OE_UNUSED(_retval);
    OE_UNUSED(oldpath);
    OE_UNUSED(newpath);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_link_ocall, oe_syscall_link_ocall);

oe_result_t _oe_syscall_unlink_ocall(int* _retval, const char* pathname)
{
    OE_UNUSED(_retval);
    OE_UNUSED(pathname);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_unlink_ocall, oe_syscall_unlink_ocall);

oe_result_t _oe_syscall_rename_ocall(
    int* _retval,
    const char* oldpath,
    const char* newpath)
{
    OE_UNUSED(_retval);
    OE_UNUSED(oldpath);
    OE_UNUSED(newpath);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_rename_ocall, oe_syscall_rename_ocall);

oe_result_t _oe_syscall_truncate_ocall(
    int* _retval,
    const char* path,
    oe_off_t length)
{
    OE_UNUSED(_retval);
    OE_UNUSED(path);
    OE_UNUSED(length);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_truncate_ocall, oe_syscall_truncate_ocall);

oe_result_t _oe_syscall_mkdir_ocall(
    int* _retval,
    const char* pathname,
    oe_mode_t mode)
{
    OE_UNUSED(_retval);
    OE_UNUSED(pathname);
    OE_UNUSED(mode);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_mkdir_ocall, oe_syscall_mkdir_ocall);

oe_result_t _oe_syscall_rmdir_ocall(int* _retval, const char* pathname)
{
    OE_UNUSED(_retval);
    OE_UNUSED(pathname);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_rmdir_ocall, oe_syscall_rmdir_ocall);

oe_result_t _oe_syscall_fcntl_ocall(
    int* _retval,
    oe_host_fd_t fd,
    int cmd,
    uint64_t arg,
    uint64_t argsize,
    void* argout)
{
    OE_UNUSED(_retval);
    OE_UNUSED(fd);
    OE_UNUSED(cmd);
    OE_UNUSED(arg);
    OE_UNUSED(argsize);
    OE_UNUSED(argout);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_fcntl_ocall, oe_syscall_fcntl_ocall);

/*
**==============================================================================
**
** ioctl.edl
**
**==============================================================================
*/

/**
 * Declare the prototypes of the following functions to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_syscall_ioctl_ocall(
    int* _retval,
    oe_host_fd_t fd,
    uint64_t request,
    uint64_t arg,
    uint64_t argsize,
    void* argout);

/**
 * Implement the functions and make them as the weak aliases of
 * the public ocall wrappers.
 */
oe_result_t _oe_syscall_ioctl_ocall(
    int* _retval,
    oe_host_fd_t fd,
    uint64_t request,
    uint64_t arg,
    uint64_t argsize,
    void* argout)
{
    OE_UNUSED(_retval);
    OE_UNUSED(fd);
    OE_UNUSED(request);
    OE_UNUSED(arg);
    OE_UNUSED(argsize);
    OE_UNUSED(argout);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_ioctl_ocall, oe_syscall_ioctl_ocall);

/*
**==============================================================================
**
** signal.edl
**
**==============================================================================
*/

/**
 * Declare the prototypes of the following functions to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_syscall_kill_ocall(int* _retval, int pid, int signum);

/**
 * Implement the functions and make them as the weak aliases of
 * the public ocall wrappers.
 */
oe_result_t _oe_syscall_kill_ocall(int* _retval, int pid, int signum)
{
    OE_UNUSED(_retval);
    OE_UNUSED(pid);
    OE_UNUSED(signum);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_kill_ocall, oe_syscall_kill_ocall);

/*
**==============================================================================
**
** socket.edl
**
**==============================================================================
*/

/**
 * Declare the prototypes of the following functions to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_syscall_close_socket_ocall(int* _retval, oe_host_fd_t sockfd);
oe_result_t _oe_syscall_socket_ocall(
    oe_host_fd_t* _retval,
    int domain,
    int type,
    int protocol);
oe_result_t _oe_syscall_shutdown_sockets_device_ocall(
    int* _retval,
    oe_host_fd_t sockfd);
oe_result_t _oe_syscall_socketpair_ocall(
    int* _retval,
    int domain,
    int type,
    int protocol,
    oe_host_fd_t sv[2]);
oe_result_t _oe_syscall_connect_ocall(
    int* _retval,
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen);
oe_result_t _oe_syscall_accept_ocall(
    oe_host_fd_t* _retval,
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out);
oe_result_t _oe_syscall_bind_ocall(
    int* _retval,
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen);
oe_result_t _oe_syscall_listen_ocall(
    int* _retval,
    oe_host_fd_t sockfd,
    int backlog);
oe_result_t _oe_syscall_recvmsg_ocall(
    ssize_t* _retval,
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
    int flags);
oe_result_t _oe_syscall_sendmsg_ocall(
    ssize_t* _retval,
    oe_host_fd_t sockfd,
    const void* msg_name,
    oe_socklen_t msg_namelen,
    void* msg_iov_buf,
    size_t msg_iovlen,
    size_t msg_iov_buf_size,
    const void* msg_control,
    size_t msg_controllen,
    int flags);
oe_result_t _oe_syscall_recv_ocall(
    ssize_t* _retval,
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags);
oe_result_t _oe_syscall_recvfrom_ocall(
    ssize_t* _retval,
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags,
    struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out);
oe_result_t _oe_syscall_send_ocall(
    ssize_t* _retval,
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags);
oe_result_t _oe_syscall_sendto_ocall(
    ssize_t* _retval,
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* dest_addr,
    oe_socklen_t addrlen);
oe_result_t _oe_syscall_recvv_ocall(
    ssize_t* _retval,
    oe_host_fd_t fd,
    void* iov_buf,
    int iovcnt,
    size_t iov_buf_size);
oe_result_t _oe_syscall_sendv_ocall(
    ssize_t* _retval,
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size);
oe_result_t _oe_syscall_shutdown_ocall(
    int* _retval,
    oe_host_fd_t sockfd,
    int how);
oe_result_t _oe_syscall_setsockopt_ocall(
    int* _retval,
    oe_host_fd_t sockfd,
    int level,
    int optname,
    const void* optval,
    oe_socklen_t optlen);
oe_result_t _oe_syscall_getsockopt_ocall(
    int* _retval,
    oe_host_fd_t sockfd,
    int level,
    int optname,
    void* optval,
    oe_socklen_t optlen_in,
    oe_socklen_t* optlen_out);
oe_result_t _oe_syscall_getsockname_ocall(
    int* _retval,
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out);
oe_result_t _oe_syscall_getpeername_ocall(
    int* _retval,
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out);
oe_result_t _oe_syscall_getaddrinfo_open_ocall(
    int* _retval,
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    uint64_t* handle);
oe_result_t _oe_syscall_getaddrinfo_read_ocall(
    int* _retval,
    uint64_t handle,
    int* ai_flags,
    int* ai_family,
    int* ai_socktype,
    int* ai_protocol,
    oe_socklen_t ai_addrlen_in,
    oe_socklen_t* ai_addrlen,
    struct oe_sockaddr* ai_addr,
    size_t ai_canonnamelen_in,
    size_t* ai_canonnamelen,
    char* ai_canonname);
oe_result_t _oe_syscall_getaddrinfo_close_ocall(int* _retval, uint64_t handle);
oe_result_t _oe_syscall_getnameinfo_ocall(
    int* _retval,
    const struct oe_sockaddr* sa,
    oe_socklen_t salen,
    char* host,
    oe_socklen_t hostlen,
    char* serv,
    oe_socklen_t servlen,
    int flags);

/**
 * Implement the functions and make them as the weak aliases of
 * the public ocall wrappers.
 */
oe_result_t _oe_syscall_close_socket_ocall(int* _retval, oe_host_fd_t sockfd)
{
    OE_UNUSED(_retval);
    OE_UNUSED(sockfd);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_close_socket_ocall, oe_syscall_close_socket_ocall);

oe_result_t _oe_syscall_socket_ocall(
    oe_host_fd_t* _retval,
    int domain,
    int type,
    int protocol)
{
    OE_UNUSED(_retval);
    OE_UNUSED(domain);
    OE_UNUSED(type);
    OE_UNUSED(protocol);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_socket_ocall, oe_syscall_socket_ocall);

oe_result_t _oe_syscall_shutdown_sockets_device_ocall(
    int* _retval,
    oe_host_fd_t sockfd)
{
    OE_UNUSED(_retval);
    OE_UNUSED(sockfd);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(
    _oe_syscall_shutdown_sockets_device_ocall,
    oe_syscall_shutdown_sockets_device_ocall);

oe_result_t _oe_syscall_socketpair_ocall(
    int* _retval,
    int domain,
    int type,
    int protocol,
    oe_host_fd_t sv[2])
{
    OE_UNUSED(_retval);
    OE_UNUSED(domain);
    OE_UNUSED(type);
    OE_UNUSED(protocol);
    OE_UNUSED(sv);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_socketpair_ocall, oe_syscall_socketpair_ocall);

oe_result_t _oe_syscall_connect_ocall(
    int* _retval,
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    OE_UNUSED(_retval);
    OE_UNUSED(sockfd);
    OE_UNUSED(addr);
    OE_UNUSED(addrlen);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_connect_ocall, oe_syscall_connect_ocall);

oe_result_t _oe_syscall_accept_ocall(
    oe_host_fd_t* _retval,
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    OE_UNUSED(_retval);
    OE_UNUSED(sockfd);
    OE_UNUSED(addr);
    OE_UNUSED(addrlen_in);
    OE_UNUSED(addrlen_out);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_accept_ocall, oe_syscall_accept_ocall);

oe_result_t _oe_syscall_bind_ocall(
    int* _retval,
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    OE_UNUSED(_retval);
    OE_UNUSED(sockfd);
    OE_UNUSED(addr);
    OE_UNUSED(addrlen);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_bind_ocall, oe_syscall_bind_ocall);

oe_result_t _oe_syscall_listen_ocall(
    int* _retval,
    oe_host_fd_t sockfd,
    int backlog)
{
    OE_UNUSED(_retval);
    OE_UNUSED(sockfd);
    OE_UNUSED(backlog);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_listen_ocall, oe_syscall_listen_ocall);

oe_result_t _oe_syscall_recvmsg_ocall(
    ssize_t* _retval,
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
    OE_UNUSED(_retval);
    OE_UNUSED(sockfd);
    OE_UNUSED(msg_name);
    OE_UNUSED(msg_namelen);
    OE_UNUSED(msg_namelen_out);
    OE_UNUSED(msg_iov_buf);
    OE_UNUSED(msg_iovlen);
    OE_UNUSED(msg_iov_buf_size);
    OE_UNUSED(msg_control);
    OE_UNUSED(msg_controllen);
    OE_UNUSED(msg_controllen_out);
    OE_UNUSED(flags);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_recvmsg_ocall, oe_syscall_recvmsg_ocall);

oe_result_t _oe_syscall_sendmsg_ocall(
    ssize_t* _retval,
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
    OE_UNUSED(_retval);
    OE_UNUSED(sockfd);
    OE_UNUSED(msg_name);
    OE_UNUSED(msg_namelen);
    OE_UNUSED(msg_iov_buf);
    OE_UNUSED(msg_iovlen);
    OE_UNUSED(msg_iov_buf_size);
    OE_UNUSED(msg_control);
    OE_UNUSED(msg_controllen);
    OE_UNUSED(flags);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_sendmsg_ocall, oe_syscall_sendmsg_ocall);

oe_result_t _oe_syscall_recv_ocall(
    ssize_t* _retval,
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags)
{
    OE_UNUSED(_retval);
    OE_UNUSED(sockfd);
    OE_UNUSED(buf);
    OE_UNUSED(len);
    OE_UNUSED(flags);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_recv_ocall, oe_syscall_recv_ocall);

oe_result_t _oe_syscall_recvfrom_ocall(
    ssize_t* _retval,
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags,
    struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    OE_UNUSED(_retval);
    OE_UNUSED(sockfd);
    OE_UNUSED(buf);
    OE_UNUSED(len);
    OE_UNUSED(flags);
    OE_UNUSED(src_addr);
    OE_UNUSED(addrlen_in);
    OE_UNUSED(addrlen_out);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_recvfrom_ocall, oe_syscall_recvfrom_ocall);

oe_result_t _oe_syscall_send_ocall(
    ssize_t* _retval,
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags)
{
    OE_UNUSED(_retval);
    OE_UNUSED(sockfd);
    OE_UNUSED(buf);
    OE_UNUSED(len);
    OE_UNUSED(flags);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_send_ocall, oe_syscall_send_ocall);

oe_result_t _oe_syscall_sendto_ocall(
    ssize_t* _retval,
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* dest_addr,
    oe_socklen_t addrlen)
{
    OE_UNUSED(_retval);
    OE_UNUSED(sockfd);
    OE_UNUSED(buf);
    OE_UNUSED(len);
    OE_UNUSED(flags);
    OE_UNUSED(dest_addr);
    OE_UNUSED(addrlen);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_sendto_ocall, oe_syscall_sendto_ocall);

oe_result_t _oe_syscall_recvv_ocall(
    ssize_t* _retval,
    oe_host_fd_t fd,
    void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    OE_UNUSED(_retval);
    OE_UNUSED(fd);
    OE_UNUSED(iov_buf);
    OE_UNUSED(iovcnt);
    OE_UNUSED(iov_buf_size);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_recvv_ocall, oe_syscall_recvv_ocall);

oe_result_t _oe_syscall_sendv_ocall(
    ssize_t* _retval,
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    OE_UNUSED(_retval);
    OE_UNUSED(fd);
    OE_UNUSED(iov_buf);
    OE_UNUSED(iovcnt);
    OE_UNUSED(iov_buf_size);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_sendv_ocall, oe_syscall_sendv_ocall);

oe_result_t _oe_syscall_shutdown_ocall(
    int* _retval,
    oe_host_fd_t sockfd,
    int how)
{
    OE_UNUSED(_retval);
    OE_UNUSED(sockfd);
    OE_UNUSED(how);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_shutdown_ocall, oe_syscall_shutdown_ocall);

oe_result_t _oe_syscall_setsockopt_ocall(
    int* _retval,
    oe_host_fd_t sockfd,
    int level,
    int optname,
    const void* optval,
    oe_socklen_t optlen)
{
    OE_UNUSED(_retval);
    OE_UNUSED(sockfd);
    OE_UNUSED(level);
    OE_UNUSED(optname);
    OE_UNUSED(optval);
    OE_UNUSED(optlen);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_setsockopt_ocall, oe_syscall_setsockopt_ocall);

oe_result_t _oe_syscall_getsockopt_ocall(
    int* _retval,
    oe_host_fd_t sockfd,
    int level,
    int optname,
    void* optval,
    oe_socklen_t optlen_in,
    oe_socklen_t* optlen_out)
{
    OE_UNUSED(_retval);
    OE_UNUSED(sockfd);
    OE_UNUSED(level);
    OE_UNUSED(optname);
    OE_UNUSED(optval);
    OE_UNUSED(optlen_in);
    OE_UNUSED(optlen_out);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getsockopt_ocall, oe_syscall_getsockopt_ocall);

oe_result_t _oe_syscall_getsockname_ocall(
    int* _retval,
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    OE_UNUSED(_retval);
    OE_UNUSED(sockfd);
    OE_UNUSED(addr);
    OE_UNUSED(addrlen_in);
    OE_UNUSED(addrlen_out);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getsockname_ocall, oe_syscall_getsockname_ocall);

oe_result_t _oe_syscall_getpeername_ocall(
    int* _retval,
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    OE_UNUSED(_retval);
    OE_UNUSED(sockfd);
    OE_UNUSED(addr);
    OE_UNUSED(addrlen_in);
    OE_UNUSED(addrlen_out);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getpeername_ocall, oe_syscall_getpeername_ocall);

oe_result_t _oe_syscall_getaddrinfo_open_ocall(
    int* _retval,
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    uint64_t* handle)
{
    OE_UNUSED(_retval);
    OE_UNUSED(node);
    OE_UNUSED(service);
    OE_UNUSED(hints);
    OE_UNUSED(handle);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(
    _oe_syscall_getaddrinfo_open_ocall,
    oe_syscall_getaddrinfo_open_ocall);

oe_result_t _oe_syscall_getaddrinfo_read_ocall(
    int* _retval,
    uint64_t handle,
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
    OE_UNUSED(_retval);
    OE_UNUSED(handle);
    OE_UNUSED(ai_flags);
    OE_UNUSED(ai_family);
    OE_UNUSED(ai_socktype);
    OE_UNUSED(ai_protocol);
    OE_UNUSED(ai_addrlen_in);
    OE_UNUSED(ai_addrlen);
    OE_UNUSED(ai_addr);
    OE_UNUSED(ai_canonnamelen_in);
    OE_UNUSED(ai_canonnamelen);
    OE_UNUSED(ai_canonname);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(
    _oe_syscall_getaddrinfo_read_ocall,
    oe_syscall_getaddrinfo_read_ocall);

oe_result_t _oe_syscall_getaddrinfo_close_ocall(int* _retval, uint64_t handle)
{
    OE_UNUSED(_retval);
    OE_UNUSED(handle);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(
    _oe_syscall_getaddrinfo_close_ocall,
    oe_syscall_getaddrinfo_close_ocall);

oe_result_t _oe_syscall_getnameinfo_ocall(
    int* _retval,
    const struct oe_sockaddr* sa,
    oe_socklen_t salen,
    char* host,
    oe_socklen_t hostlen,
    char* serv,
    oe_socklen_t servlen,
    int flags)
{
    OE_UNUSED(_retval);
    OE_UNUSED(sa);
    OE_UNUSED(salen);
    OE_UNUSED(host);
    OE_UNUSED(hostlen);
    OE_UNUSED(serv);
    OE_UNUSED(servlen);
    OE_UNUSED(flags);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getnameinfo_ocall, oe_syscall_getnameinfo_ocall);

/*
**==============================================================================
**
** poll.edl
**
**==============================================================================
*/

/**
 * Declare the prototypes of the following functions to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_syscall_poll_ocall(
    int* _retval,
    struct oe_host_pollfd* host_fds,
    oe_nfds_t nfds,
    int timeout);

/**
 * Implement the functions and make them as the weak aliases of
 * the public ocall wrappers.
 */
oe_result_t _oe_syscall_poll_ocall(
    int* _retval,
    struct oe_host_pollfd* host_fds,
    oe_nfds_t nfds,
    int timeout)
{
    OE_UNUSED(_retval);
    OE_UNUSED(host_fds);
    OE_UNUSED(nfds);
    OE_UNUSED(timeout);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_poll_ocall, oe_syscall_poll_ocall);

/*
**==============================================================================
**
** time.edl
**
**==============================================================================
*/

/**
 * Declare the prototypes of the following functions to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_syscall_nanosleep_ocall(
    int* _retval,
    struct oe_timespec* req,
    struct oe_timespec* rem);

/**
 * Implement the functions and make them as the weak aliases of
 * the public ocall wrappers.
 */
oe_result_t _oe_syscall_nanosleep_ocall(
    int* _retval,
    struct oe_timespec* req,
    struct oe_timespec* rem)
{
    OE_UNUSED(_retval);
    OE_UNUSED(req);
    OE_UNUSED(rem);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_nanosleep_ocall, oe_syscall_nanosleep_ocall);

/*
**==============================================================================
**
** unistd.edl
**
**==============================================================================
*/

/**
 * Declare the prototypes of the following functions to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_syscall_getpid_ocall(int* _retval);
oe_result_t _oe_syscall_getppid_ocall(int* _retval);
oe_result_t _oe_syscall_getpgrp_ocall(int* _retval);
oe_result_t _oe_syscall_getuid_ocall(unsigned int* _retval);
oe_result_t _oe_syscall_geteuid_ocall(unsigned int* _retval);
oe_result_t _oe_syscall_getgid_ocall(unsigned int* _retval);
oe_result_t _oe_syscall_getegid_ocall(unsigned int* _retval);
oe_result_t _oe_syscall_getpgid_ocall(int* _retval, int pid);
oe_result_t _oe_syscall_getgroups_ocall(
    int* _retval,
    size_t size,
    unsigned int* list);

/**
 * Implement the functions and make them as the weak aliases of
 * the public ocall wrappers.
 */
oe_result_t _oe_syscall_getpid_ocall(int* _retval)
{
    OE_UNUSED(_retval);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getpid_ocall, oe_syscall_getpid_ocall);

oe_result_t _oe_syscall_getppid_ocall(int* _retval)
{
    OE_UNUSED(_retval);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getppid_ocall, oe_syscall_getppid_ocall);

oe_result_t _oe_syscall_getpgrp_ocall(int* _retval)
{
    OE_UNUSED(_retval);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getpgrp_ocall, oe_syscall_getpgrp_ocall);

oe_result_t _oe_syscall_getuid_ocall(unsigned int* _retval)
{
    OE_UNUSED(_retval);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getuid_ocall, oe_syscall_getuid_ocall);

oe_result_t _oe_syscall_geteuid_ocall(unsigned int* _retval)
{
    OE_UNUSED(_retval);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_geteuid_ocall, oe_syscall_geteuid_ocall);

oe_result_t _oe_syscall_getgid_ocall(unsigned int* _retval)
{
    OE_UNUSED(_retval);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getgid_ocall, oe_syscall_getgid_ocall);

oe_result_t _oe_syscall_getegid_ocall(unsigned int* _retval)
{
    OE_UNUSED(_retval);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getegid_ocall, oe_syscall_getegid_ocall);

oe_result_t _oe_syscall_getpgid_ocall(int* _retval, int pid)
{
    OE_UNUSED(_retval);
    OE_UNUSED(pid);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getpgid_ocall, oe_syscall_getpgid_ocall);

oe_result_t _oe_syscall_getgroups_ocall(
    int* _retval,
    size_t size,
    unsigned int* list)
{
    OE_UNUSED(_retval);
    OE_UNUSED(size);
    OE_UNUSED(list);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getgroups_ocall, oe_syscall_getgroups_ocall);

/*
**==============================================================================
**
** utsname.edl
**
**==============================================================================
*/

/**
 * Declare the prototypes of the following functions to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_syscall_uname_ocall(int* _retval, struct oe_utsname* buf);

/**
 * Implement the functions and make them as the weak aliases of
 * the public ocall wrappers.
 */
oe_result_t _oe_syscall_uname_ocall(int* _retval, struct oe_utsname* buf)
{
    OE_UNUSED(_retval);
    OE_UNUSED(buf);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_uname_ocall, oe_syscall_uname_ocall);

#endif
