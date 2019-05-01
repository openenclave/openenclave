// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
**==============================================================================
**
** windows/posix.c:
**
**     This file implements POSIX OCALLs for Windows. Most of these are stubs
**     which are still under development.
**
**==============================================================================
*/

#include <io.h>
#include <stdint.h>

#include "posix_u.h"

/*
**==============================================================================
**
** Local definitions.
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

#define PANIC _panic(__FILE__, __LINE__, __FUNCTION__);

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
    oe_mode_t mode)

{
     int ret = -1;

     if (strcmp(pathname, "/dev/stdin") == 0)
     {
         if ((flags & 0x00000003) != OE_O_RDONLY)
         {
             if (err)
                 *err = EINVAL;
             goto done;
         }

         ret = (__int64) GetStdHandle(STD_INPUT_HANDLE);
     }
     else if (strcmp(pathname, "/dev/stdout") == 0)
     {
         if ((flags & 0x00000003) != OE_O_WRONLY)
         {
             if (err)
                 *err = EINVAL;
             goto done;
         }

         ret = (__int64) GetStdHandle(STD_OUTPUT_HANDLE);
     }
     else if (strcmp(pathname, "/dev/stderr") == 0)
     {
         if ((flags & 0x00000003) != OE_O_WRONLY)
         {
             if (err)
                 *err = EINVAL;
             goto done;
         }

         ret = (__int64) GetStdHandle(STD_ERROR_HANDLE);
     }
     else
     {
         DWORD desired_access = 0;
         DWORD share_mode     = 0;
         DWORD create_dispos  = 0;
        
    
         int nLen = MultiByteToWideChar(CP_UTF8, 0, pathname, -1, NULL, NULL);
         WCHAR *wpathname = (WCHAR *)(calloc((nLen+1)*sizeof(wchar)));
         MultiByteToWideChar(CP_UTF8, 0, pathname, -1, wpathname, nLen);
       
         if ((flags & OE_O_DIRECTORY) != 0)
         {
            // 2Do  call Opendir
         }
      
         /* Open flags are neither a bitmask nor a sequence, so switching or maskign don't really work. */
      
         if ((flags & OE_O_CREAT) != 0)
         {
            desired_access |= OPEN_ALWAYS;
         }
         else {
             if ((flags & OE_O_TRUNC) != 0)
             {
                 desired_acces = TRUNCATE_EXISTING;
             }
             else if ((flags & OE_O_APPEND) != 0)
             {
                 desired_acces = OPEN_EXISTING;
             }
         }
    
         const int ACCESS_FLAGS = 0x3;   // Covers rdonly, wronly rdwr
         switch ((flags & ACCESS_FLAGS) != 0)
         {
         case OE_O_RDONLY:
             desired_access = GENERIC_READ;
             share_mode = FILE_SHARE_READ;
             break;

         case OE_O_WRONLY:
             desired_access = GENERIC_WRITE;
             share_mode = FILE_SHARE_WRITE;
             break;

         case OE_O_RDWR:
             desired_access = GENERIC_READ | GENERIC_WRITE;
             share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
             break;

         default:
             break;
         }

         ret = CreateFileW(wpathname, desired_access, share_mode, NULL, create_dispos,
                      (FILE_ATTRIBUTE_NORMAL|FILE_FLAG_POSIX_SEMANTICS));
    }

}

ssize_t oe_posix_read_ocall(oe_host_fd_t fd, void* buf, size_t count)
{
    /* ATTN: casting 64-bit fd to 32-bit fd */
    return _read((int)fd, buf, (uint32_t)count);
}

ssize_t oe_posix_write_ocall(oe_host_fd_t fd, const void* buf, size_t count)
{
    /* ATTN: casting 64-bit fd to 32-bit fd */
    return _write((int)fd, buf, (uint32_t)count);
}

oe_off_t oe_posix_lseek_ocall(oe_host_fd_t fd, oe_off_t offset, int whence)
{
    PANIC;
}

int oe_posix_close_ocall(oe_host_fd_t fd)
{
    PANIC;
}

oe_host_fd_t oe_posix_dup_ocall(oe_host_fd_t oldfd)
{
    PANIC;
}

uint64_t oe_posix_opendir_ocall(const char* name)
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
    size_t d_namelen)
{
    PANIC;
}

void oe_posix_rewinddir_ocall(uint64_t dirp)
{
}

int oe_posix_closedir_ocall(uint64_t dirp)
{
    PANIC;
}

int oe_posix_stat_ocall(const char* pathname, struct oe_stat* buf)
{
    PANIC;
}

int oe_posix_access_ocall(const char* pathname, int mode)
{
    PANIC;
}

int oe_posix_link_ocall(const char* oldpath, const char* newpath)
{
    PANIC;
}

int oe_posix_unlink_ocall(const char* pathname)
{
    PANIC;
}

int oe_posix_rename_ocall(const char* oldpath, const char* newpath)
{
    PANIC;
}

int oe_posix_truncate_ocall(const char* path, oe_off_t length)
{
    PANIC;
}

int oe_posix_mkdir_ocall(const char* pathname, oe_mode_t mode)
{
    PANIC;
}

int oe_posix_rmdir_ocall(const char* pathname)
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

oe_host_fd_t oe_posix_socket_ocall(int domain, int type, int protocol)
{
    PANIC;
}

int oe_posix_socketpair_ocall(
    int domain,
    int type,
    int protocol,
    oe_host_fd_t sv_out[2])
{
    PANIC;
}

int oe_posix_connect_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    PANIC;
}

oe_host_fd_t oe_posix_accept_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    PANIC;
}

int oe_posix_bind_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    PANIC;
}

int oe_posix_listen_ocall(oe_host_fd_t sockfd, int backlog)
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
    int flags)
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
    int flags)
{
    PANIC;
}

ssize_t oe_posix_recv_ocall(
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags)
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
    oe_socklen_t* addrlen_out)
{
    PANIC;
}

ssize_t oe_posix_send_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags)
{
    PANIC;
}

ssize_t oe_posix_sendto_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen)
{
    PANIC;
}

int oe_posix_shutdown_ocall(oe_host_fd_t sockfd, int how)
{
    PANIC;
}

int oe_posix_fcntl_ocall(oe_host_fd_t fd, int cmd, uint64_t arg)
{
    PANIC;
}

int oe_posix_setsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    const void* optval,
    oe_socklen_t optlen)
{
    PANIC;
}

int oe_posix_getsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    void* optval,
    oe_socklen_t optlen_in,
    oe_socklen_t* optlen_out)
{
    PANIC;
}

int oe_posix_getsockname_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    PANIC;
}

int oe_posix_getpeername_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    PANIC;
}

int oe_posix_shutdown_sockets_device_ocall(oe_host_fd_t sockfd)
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

int oe_posix_kill_ocall(int pid, int signum)
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
    const struct oe_addrinfo* hints)
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
    char* ai_canonname)
{
    PANIC;
}

int oe_posix_getaddrinfo_close_ocall(uint64_t handle_)
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
    int flags)
{
    PANIC;
}

int oe_posix_shutdown_resolver_device_ocall()
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

oe_host_fd_t oe_posix_epoll_create1_ocall(int flags)
{
    PANIC;
}

int oe_posix_epoll_wait_async_ocall(
    int64_t enclaveid,
    oe_host_fd_t epfd,
    size_t maxevents)
{
    PANIC;
}

int oe_posix_epoll_ctl_add_ocall(
    oe_host_fd_t epfd,
    oe_host_fd_t fd,
    unsigned int event_mask,
    int list_idx,
    int epoll_enclave_fd)
{
    PANIC;
}

int oe_posix_epoll_ctl_del_ocall(oe_host_fd_t epfd, oe_host_fd_t fd)
{
    PANIC;
}

int oe_posix_epoll_ctl_mod_ocall(
    oe_host_fd_t epfd,
    oe_host_fd_t fd,
    unsigned int event_mask,
    int list_idx,
    int enclave_fd)
{
    PANIC;
}

int oe_posix_epoll_close_ocall(oe_host_fd_t fd)
{
    PANIC;
}

int oe_posix_shutdown_polling_device_ocall(oe_host_fd_t fd)
{
    PANIC;
}

int oe_posix_epoll_poll_ocall(
    int64_t enclaveid,
    oe_host_fd_t epfd,
    struct oe_pollfd* fds,
    size_t nfds,
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

int oe_posix_getpgid(int pid)
{
    PANIC;
}

int oe_posix_getgroups(size_t size, unsigned int* list)
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

int oe_posix_uname_ocall(struct oe_utsname* buf)
{
    PANIC;
}
