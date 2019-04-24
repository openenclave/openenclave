// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

typedef __int64 off_t;
#include <openenclave/internal/posix/hostfs.h>
#if defined(NOTYET)
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <io.h>
#include <stdint.h>
#pragma warning(disable:4005)
#include "oe_u.h"


OE_INLINE void _set_err(int* err, int num)
{
    if (err)
        *err = num;
}

OE_INLINE void _clear_err(int* err)
{
    if (err)
        *err = 0;
}

/*
**==============================================================================
**
** File I/O:
**
**==============================================================================
*/

int oe_posix_open_ocall(const char* pathname, int flags, mode_t mode, int* err)
{
    int ret = -1;

#if defined(NOTYET)
    if (strcmp(pathname, "/dev/stdin") == 0)
    {
        if ((flags & 0x00000003) != O_RDONLY)
        {
            if (err)
                *err = EINVAL;

            goto done;
        }

        ret = STDIN_FILENO;
    }
    else if (strcmp(pathname, "/dev/stdout") == 0)
    {
        if ((flags & 0x00000003) != O_WRONLY)
        {
            if (err)
                *err = EINVAL;

            goto done;
        }

        ret = STDOUT_FILENO;
    }
    else if (strcmp(pathname, "/dev/stderr") == 0)
    {
        if ((flags & 0x00000003) != O_WRONLY)
        {
            if (err)
                *err = EINVAL;

            goto done;
        }

        ret = STDERR_FILENO;
    }
    else
    {

        ret = open(pathname, flags, mode);

        if (ret == -1 && err)
            *err = errno;
    }
#else
        ret = -1;
        _set_err(err, 38); // ENOSYS
	goto done;
#endif

done:
    return ret;
}

ssize_t oe_posix_read_ocall(int fd, void* buf, size_t count, int* err)
{
    ssize_t ret = _read(fd, buf, (uint32_t)count);

    if (ret == -1 && err)
        *err = errno;

    return ret;
}

ssize_t oe_posix_write_ocall(int fd, const void* buf, size_t count, int* err)
{
    ssize_t ret = _write(fd, buf, (uint32_t)count);

    if (ret == -1 && err)
        *err = errno;

    return ret;
}

off_t oe_posix_lseek_ocall(int fd, off_t offset, int whence, int* err)
{
#if defined(NOTYET)
    off_t ret = lseek(fd, offset, whence); 2DO

    if (ret == -1 && err)
        *err = errno;
#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

int oe_posix_close_ocall(int fd, int* err)
{
#if defined(NOTYET)
    int ret = close(fd);

    if (ret != 0 && err)
    {
        if (err)
            *err = errno;
    }
#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

int oe_posix_dup_ocall(int oldfd, int* err)
{
#if defined(NOTYET)
    int ret = dup(oldfd);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }
#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

uint64_t oe_posix_opendir_ocall(const char* name, int* err)
{
#if defined(NOTYET)
    void* ret = opendir(name);

    if (!ret && err)
        *err = errno;

#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif
    return (uint64_t)ret;
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
    int ret = -1;
#if defined(NOTYET)
    struct dirent* ent;

    _clear_err(err);

    if (!dirp)
    {
        _set_err(err, EBADF);
        goto done;
    }

    if (!d_ino || !d_off || !d_reclen || !d_type || !d_name)
    {
        _set_err(err, EINVAL);
        goto done;
    }

    errno = 0;

    if (!(ent = readdir((DIR*)dirp)))
    {
        if (errno)
        {
            _set_err(err, errno);
            goto done;
        }

        ret = -1;
        goto done;
    }

    {
        size_t len = strlen(ent->d_name);

        oe_assign_uint64(d_ino, &ent->d_ino);
        oe_assign_int64(d_off, &ent->d_off);
        oe_assign_uint16(d_reclen, &ent->d_reclen);
        oe_assign_uint8(d_type, &ent->d_type);

        if (len >= d_namelen)
        {
            _set_err(err, ENAMETOOLONG);
            goto done;
        }

        memcpy(d_name, ent->d_name, len + 1);
    }

    ret = 0;
#else
    _set_err(err, 38); // ENOSYS
    ret = -1;
    goto done;
#endif

done:
    return ret;
}

void oe_posix_rewinddir_ocall(uint64_t dirp)
{
//    rewinddir((DIR*)dirp); 2do
}

int oe_posix_closedir_ocall(uint64_t dirp, int* err)
{
#if defined(NOTYET)
    int ret = closedir((DIR*)dirp);

    if (ret != 0 && err)
        *err = errno;
#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

int oe_posix_stat_ocall(
    const char* pathname,
    uint64_t* st_dev,
    uint64_t* st_ino,
    uint64_t* st_nlink,
    uint32_t* st_mode,
    uint32_t* st_uid,
    uint32_t* st_gid,
    uint64_t* st_rdev,
    int64_t* st_size,
    int64_t* st_blksize,
    int64_t* st_blocks,
    int64_t* st_atim_tv_sec,
    int64_t* st_atim_tv_nsec,
    int64_t* st_mtim_tv_sec,
    int64_t* st_mtim_tv_nsec,
    int64_t* st_ctim_tv_sec,
    int64_t* st_ctim_tv_nsec,
    int* err)
{
    int ret = -1;
#if defined(NOTYET)
    struct stat st;

    errno = 0;
    _clear_err(err);

    if (!st_dev || !st_ino || !st_nlink || !st_mode || !st_uid || !st_gid ||
        !st_rdev || !st_size || !st_blksize || !st_blocks || !st_atim_tv_sec ||
        !st_atim_tv_nsec || !st_ctim_tv_sec || !st_ctim_tv_nsec ||
        !st_mtim_tv_sec || !st_mtim_tv_nsec)
    {
        goto done;
    }

    if ((ret = stat(pathname, &st)) == -1)
    {
        _set_err(err, errno);
        goto done;
    }

    oe_assign_uint64(st_dev, &st.st_dev);
    oe_assign_uint64(st_dev, &st.st_dev);
    oe_assign_uint64(st_ino, &st.st_ino);
    oe_assign_uint64(st_nlink, &st.st_nlink);
    oe_assign_uint32(st_mode, &st.st_mode);
    oe_assign_uint32(st_uid, &st.st_uid);
    oe_assign_uint32(st_gid, &st.st_gid);
    oe_assign_uint64(st_rdev, &st.st_rdev);
    oe_assign_int64(st_size, &st.st_size);
    oe_assign_int64(st_blksize, &st.st_blksize);
    oe_assign_int64(st_blocks, &st.st_blocks);
    oe_assign_int64(st_atim_tv_sec, &st.st_atim.tv_sec);
    oe_assign_int64(st_atim_tv_nsec, &st.st_atim.tv_nsec);
    oe_assign_int64(st_mtim_tv_sec, &st.st_mtim.tv_sec);
    oe_assign_int64(st_mtim_tv_nsec, &st.st_mtim.tv_nsec);
    oe_assign_int64(st_ctim_tv_sec, &st.st_ctim.tv_sec);
    oe_assign_int64(st_ctim_tv_nsec, &st.st_ctim.tv_nsec);
#else
    _set_err(err, 38); // ENOSYS
    ret = -1;
    goto done;
#endif

done:
    return ret;
}

int oe_posix_access_ocall(const char* pathname, int mode, int* err)
{
#if defined(NOTYET)
    int ret = access(pathname, mode);

    if (ret != 0 && err)
        *err = errno;

#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif
    return ret;
}

int oe_posix_link_ocall(const char* oldpath, const char* newpath, int* err)
{
#if defined(NOTYET)
    int ret = link(oldpath, newpath);

    if (ret != 0 && err)
        *err = errno;
#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

int oe_posix_unlink_ocall(const char* pathname, int* err)
{
#if defined(NOTYET)
    int ret = unlink(pathname);

    if (ret != 0 && err)
        *err = errno;
#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

int oe_posix_rename_ocall(const char* oldpath, const char* newpath, int* err)
{
#if defined(NOTYET)
    int ret = rename(oldpath, newpath);

    if (ret != 0 && err)
        *err = errno;
#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif
    return ret;
}

int oe_posix_truncate_ocall(const char* path, off_t length, int* err)
{
#if defined(NOTYET)
    int ret = truncate(path, length);

    if (ret != 0 && err)
        *err = errno;

#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif
    return ret;
}

int oe_posix_mkdir_ocall(const char* pathname, mode_t mode, int* err)
{
#if defined(NOTYET)
    int ret = mkdir(pathname, mode);

    if (ret != 0 && err)
        *err = errno;
#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

int oe_posix_rmdir_ocall(const char* pathname, int* err)
{
#if defined(NOTYET)
    int ret = rmdir(pathname);

    if (ret != 0 && err)
        *err = errno;

#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif
    return ret;
}

/*
**==============================================================================
**
** Socket I/O:
**
**==============================================================================
*/

int oe_posix_socket_ocall(int domain, int type, int protocol, int* err)
{
#if defined(NOTYET)
    int ret = socket(domain, type, protocol);

    if (ret == -1 && err)
        *err = errno;

#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif
    return ret;
}

int oe_posix_socketpair_ocall(
    int domain,
    int type,
    int protocol,
    int sv[2],
    int* err)
{
#if defined(NOTYET)
    int ret = socketpair(domain, type, protocol, sv);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }
#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

int oe_posix_connect_ocall(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen,
    int* err)
{
#if defined(NOTYET)
    int ret = connect(sockfd, addr, addrlen);

    if (ret == -1 && err)
        *err = errno;

#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif
    return ret;
}

int oe_posix_accept_ocall(
    int sockfd,
    struct sockaddr* addr,
    socklen_t addrlen_in,
    socklen_t* addrlen_out,
    int* err)
{
#if defined(NOTYET)
    int ret = accept(sockfd, addr, &addrlen_in);

    if (ret == -1)
    {
        if (err)
            *err = errno;

        goto done;
    }

    if (addrlen_out)
        *addrlen_out = addrlen_in;

done:
#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif
    return ret;
}

int oe_posix_bind_ocall(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen,
    int* err)
{
#if defined(NOTYET)
    int ret = bind(sockfd, addr, addrlen);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }
#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

int oe_posix_listen_ocall(int sockfd, int backlog, int* err)
{
#if defined(NOTYET)
    errno = 0;

    int ret = listen(sockfd, backlog);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif
    return ret;
}

ssize_t oe_posix_recvmsg_ocall(
    int sockfd,
    void* msg_name,
    socklen_t msg_namelen,
    socklen_t* msg_namelen_out,
    void* msg_buf,
    size_t msg_buflen,
    void* msg_control,
    size_t msg_controllen,
    size_t* msg_controllen_out,
    int flags,
    int* err)
{
    ssize_t ret = -1;
#if defined(NOTYET)
    struct msghdr msg;
    struct iovec iov;

    if (err)
        *err = 0;

    iov.iov_base = msg_buf;
    iov.iov_len = msg_buflen;
    msg.msg_name = msg_name;
    msg.msg_namelen = msg_namelen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = msg_control;
    msg.msg_controllen = msg_controllen;
    msg.msg_flags = 0;

    if ((ret = recvmsg(sockfd, &msg, flags)) == -1)
    {
        if (err)
            *err = errno;

        goto done;
    }

    if (*msg_namelen_out)
        *msg_namelen_out = msg.msg_namelen;

    if (*msg_controllen_out)
        *msg_controllen_out = msg.msg_controllen;

done:
#else
    ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

ssize_t oe_posix_sendmsg_ocall(
    int sockfd,
    const void* msg_name,
    socklen_t msg_namelen,
    const void* msg_buf,
    size_t msg_buflen,
    const void* msg_control,
    size_t msg_controllen,
    int flags,
    int* err)
{
    ssize_t ret = -1;
#if defined(NOTYET)
    struct msghdr msg;
    struct iovec iov;

    if (err)
        *err = 0;

    iov.iov_base = (void*)msg_buf;
    iov.iov_len = msg_buflen;
    msg.msg_name = (void*)msg_name;
    msg.msg_namelen = msg_namelen;
    msg.msg_iov = (void*)&iov;
    msg.msg_iovlen = 1;
    msg.msg_control = (void*)msg_control;
    msg.msg_controllen = msg_controllen;
    msg.msg_flags = 0;

    if ((ret = sendmsg(sockfd, &msg, flags)) == -1)
    {
        if (err)
            *err = errno;
    }
#else
    ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

#if 0
ssize_t oe_posix_sendmsg_ocall(
    int sockfd,
    const struct msghdr* msg,
    int flags,
    int* err)
{
}
#endif

ssize_t oe_posix_recv_ocall(
    int sockfd,
    void* buf,
    size_t len,
    int flags,
    int* err)
{
#if defined(NOTYET)
    ssize_t ret = recv(sockfd, buf, len, flags);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }
#else
    ssize_t ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

/* ATTN:IO: add test for this function. */
ssize_t oe_posix_recvfrom_ocall(
    int sockfd,
    void* buf,
    size_t len,
    int flags,
    struct sockaddr* src_addr,
    socklen_t addrlen_in,
    socklen_t* addrlen_out,
    int* err)
{
#if defined(NOTYET)
    ssize_t ret = recvfrom(sockfd, buf, len, flags, src_addr, &addrlen_in);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    if (addrlen_out)
        *addrlen_out = addrlen_in;
#else
    ssize_t ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

ssize_t oe_posix_send_ocall(
    int sockfd,
    const void* buf,
    size_t len,
    int flags,
    int* err)
{
#if defined(NOTYET)
    ssize_t ret = send(sockfd, buf, len, flags);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }
#else
    ssize_t ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

/* ATTN:IO: add test for this function. */
ssize_t oe_posix_sendto_ocall(
    int sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct sockaddr* src_addr,
    socklen_t addrlen,
    int* err)
{
#if defined(NOTYET)
    ssize_t ret = sendto(sockfd, buf, len, flags, src_addr, addrlen);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }
#else
    ssize_t ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

int oe_posix_shutdown_ocall(int sockfd, int how, int* err)
{
#if defined(NOTYET)
    int ret = shutdown(sockfd, how);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }
#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

int oe_posix_fcntl_ocall(int fd, int cmd, uint64_t arg, int* err)
{
    int ret;

#if defined(NOTYET)
    if (err)
        *err = 0;

    if ((ret = fcntl(fd, cmd, arg)) == -1)
    {
        if (err)
            *err = errno;
    }
#else
    ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

int oe_posix_setsockopt_ocall(
    int sockfd,
    int level,
    int optname,
    const void* optval,
    socklen_t optlen,
    int* err)
{
    int ret = -1;

    errno = 0;

#if defined(NOTYET)
    ret = setsockopt(sockfd, level, optname, optval, optlen);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }
#else
    ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

int oe_posix_getsockopt_ocall(
    int sockfd,
    int level,
    int optname,
    void* optval,
    socklen_t optlen_in,
    socklen_t* optlen,
    int* err)
{
    int ret;

#if defined(NOTYET)
    if (optlen)
        *optlen = optlen_in;

    ret = getsockopt(sockfd, level, optname, optval, optlen);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }
#else
    ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

int oe_posix_getsockname_ocall(
    int sockfd,
    struct sockaddr* addr,
    socklen_t addrlen_in,
    socklen_t* addrlen_out,
    int* err)
{
#if defined(NOTYET)
    if (addrlen_out)
        *addrlen_out = addrlen_in;

    int ret = getsockname(sockfd, addr, addrlen_out);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }
#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

int oe_posix_getpeername_ocall(
    int sockfd,
    struct sockaddr* addr,
    socklen_t addrlen_in,
    socklen_t* addrlen_out,
    int* err)
{
#if defined(NOTYET)
    if (addrlen_out)
        *addrlen_out = addrlen_in;

    int ret = getpeername(sockfd, addr, addrlen_out);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }
#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

int oe_posix_shutdown_sockets_device_ocall(int sockfd, int* err)
{
    OE_UNUSED(sockfd);

    /* No shutdown actions needed for this device. */

    if (err)
        *err = 0;

    return 0;
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
    int ret = -1;
#if defined(NOTYET)

    *err = 0;

    ret = kill(pid, signum);

    if (ret < 0)
    {
        if (err)
            *err = errno;
    }
#else
    ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

/*
**==============================================================================
**
** Resolver:
**
**==============================================================================
*/

#define GETADDRINFO_HANDLE_MAGIC 0xed11d13a

typedef struct _getaddrinfo_handle
{
    uint32_t magic;
    struct addrinfo* res;
    struct addrinfo* next;
} getaddrinfo_handle_t;

static getaddrinfo_handle_t* _cast_getaddrinfo_handle(void* handle_)
{
    getaddrinfo_handle_t* handle = (getaddrinfo_handle_t*)handle_;

    if (!handle || handle->magic != GETADDRINFO_HANDLE_MAGIC || !handle->res)
        return NULL;

    return handle;
}

uint64_t oe_posix_getaddrinfo_open_ocall(
    const char* node,
    const char* service,
    const struct addrinfo* hints,
    int* err)
{
#if defined(NOTYET)
    getaddrinfo_handle_t* ret = NULL;
    getaddrinfo_handle_t* handle = NULL;

    if (err)
        *err = 0;

    if (!(handle = calloc(1, sizeof(getaddrinfo_handle_t))))
    {
        _set_err(err, ENOMEM);
        goto done;
    }

    if (getaddrinfo(node, service, hints, &handle->res) != 0)
    {
        _set_err(err, errno);
        goto done;
    }

    handle->magic = GETADDRINFO_HANDLE_MAGIC;
    handle->next = handle->res;
    ret = handle;
    handle = NULL;

done:

    if (handle)
        free(handle);
#else
   int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return (uint64_t)ret;
}

int oe_posix_getaddrinfo_read_ocall(
    uint64_t handle_,
    int* ai_flags,
    int* ai_family,
    int* ai_socktype,
    int* ai_protocol,
    socklen_t ai_addrlen_in,
    socklen_t* ai_addrlen,
    struct sockaddr* ai_addr,
    size_t ai_canonnamelen_in,
    size_t* ai_canonnamelen,
    char* ai_canonname,
    int* err)
{
    int ret = -1;
#if defined(NOTYET)
    getaddrinfo_handle_t* handle = _cast_getaddrinfo_handle((void*)handle_);

    if (err)
        *err = 0;

    if (!handle || !ai_flags || !ai_family || !ai_socktype || !ai_protocol ||
        !ai_addrlen || !ai_canonnamelen || !err)
    {
        _set_err(err, EINVAL);
        goto done;
    }

    if (!ai_addr && ai_addrlen_in)
    {
        _set_err(err, EINVAL);
        goto done;
    }

    if (!ai_canonname && ai_canonnamelen_in)
    {
        _set_err(err, EINVAL);
        goto done;
    }

    if (handle->next)
    {
        struct addrinfo* p = handle->next;

        *ai_flags = p->ai_flags;
        *ai_family = p->ai_family;
        *ai_socktype = p->ai_socktype;
        *ai_protocol = p->ai_protocol;
        *ai_addrlen = p->ai_addrlen;

        if (p->ai_canonname)
            *ai_canonnamelen = strlen(p->ai_canonname) + 1;
        else
            *ai_canonnamelen = 0;

        if (*ai_addrlen > ai_addrlen_in)
        {
            _set_err(err, ENAMETOOLONG);
            goto done;
        }

        if (*ai_canonnamelen > ai_canonnamelen_in)
        {
            _set_err(err, ENAMETOOLONG);
            goto done;
        }

        memcpy(ai_addr, p->ai_addr, *ai_addrlen);

        if (p->ai_canonname)
            memcpy(ai_canonname, p->ai_canonname, *ai_canonnamelen);

        handle->next = handle->next->ai_next;

        ret = 0;
        goto done;
    }
    else
    {
        /* Done */
        ret = 1;
        goto done;
    }
#else
    ret = -1;
    _set_err(err, 38); // ENOSYS
    goto done;
#endif

done:
    return ret;
}

int oe_posix_getaddrinfo_close_ocall(uint64_t handle_, int* err)
{
    int ret = -1;
#if defined(NOTYET)
    getaddrinfo_handle_t* handle = _cast_getaddrinfo_handle((void*)handle_);

    if (err)
        *err = 0;

    if (!handle)
    {
        _set_err(err, EINVAL);
        goto done;
    }

    freeaddrinfo(handle->res);
    free(handle);

    ret = 0;
#else
    ret = -1;
    _set_err(err, 38); // ENOSYS
    goto done;
#endif

done:
    return ret;
}

int oe_posix_getnameinfo_ocall(
    const struct sockaddr* sa,
    socklen_t salen,
    char* host,
    socklen_t hostlen,
    char* serv,
    socklen_t servlen,
    int flags,
    int* err)
{
#if defined(NOTYET)
    int ret = getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);

    if (ret == EAI_SYSTEM)
    {
        if (err)
            *err = errno;
    }
#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

int oe_posix_shutdown_resolver_device_ocall(int* err)
{
    /* No shutdown actions needed for this device. */

    if (err)
        *err = 0;

    return 0;
}

/*
**==============================================================================
**
** Polling:
**
**==============================================================================
*/

#if defined(NOTYET)
typedef struct _wait_args
{
    int64_t enclaveid;
    int epfd;
    int maxevents;
    struct epoll_event events[];
} wait_args_t;

static void* epoll_wait_thread(void* arg_)
{
    int ret = 0;
#if defined(NOTYET)
    wait_args_t* args = (wait_args_t*)arg_;
    int retval;

    ret = epoll_wait(args->epfd, args->events, args->maxevents, -1);

    if (ret >= 0)
    {
        size_t num_notifications = (size_t)ret;
        struct epoll_event* ev = args->events;
        oe_device_notifications_t* notifications =
            (oe_device_notifications_t*)ev;

        OE_STATIC_ASSERT(sizeof(notifications[0]) == sizeof(ev[0]));

        if (oe_posix_polling_notify_ecall(
                (oe_enclave_t*)args->enclaveid,
                &retval,
                notifications,
                num_notifications) != OE_OK)
        {
            goto done;
        }

        if (retval != 0)
            goto done;
    }
#else
    ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

done:
    free(args);
    return NULL;
}

typedef struct _poll_args
{
    int64_t enclaveid;
    int epfd;
    nfds_t nfds;
    struct pollfd fds[];
} poll_args_t;

static void* poll_wait_thread(void* arg_)
{
    int ret = 0;
    poll_args_t* args = (poll_args_t*)arg_;
    int retval;

    ret = poll(args->fds, args->nfds, -1);
    if (ret >= 0)
    {
        size_t num_notifications = (size_t)ret;
        struct pollfd* ev = args->fds;
        oe_device_notifications_t* notifications =
            (oe_device_notifications_t*)ev;

        size_t ev_idx = 0;
        size_t notify_idx = 0;
        for (ev_idx = 0; ev_idx < (size_t)args->nfds; ev_idx++)
        {
            if (ev[ev_idx].revents)
            {
                notifications[notify_idx].event_mask =
                    (uint32_t)ev[ev_idx].revents;
                notifications[notify_idx].list_idx = (uint32_t)ev_idx;
                notifications[notify_idx].epoll_fd = (uint32_t)args->epfd;
            }
        }

        if (oe_posix_polling_notify_ecall(
                (oe_enclave_t*)args->enclaveid,
                &retval,
                notifications,
                num_notifications) != OE_OK)
        {
            goto done;
        }

        if (retval != 0)
            goto done;
    }

done:
    free(args);
    return NULL;
}
#endif

int oe_posix_epoll_create1_ocall(int flags, int* err)
{
#if defined(NOTYET)
    int ret = epoll_create1(flags);

    if (ret == -1)
        _set_err(err, errno);
#else
    int ret = -1;
    _set_err(err, 38); // ENOSYS
#endif

    return ret;
}

int oe_posix_epoll_wait_async_ocall(
    int64_t enclaveid,
    int epfd,
    size_t maxevents,
    int* err)
{
    int ret = -1;
#if defined(NOTYET)
    size_t eventsize;
    pthread_t thread = 0;
    wait_args_t* args = NULL;

    eventsize = sizeof(struct oe_epoll_event) * maxevents;

    if (!(args = calloc(1, sizeof(wait_args_t) + eventsize)))
    {
        _set_err(err, ENOMEM);
        goto done;
    }

    args->enclaveid = enclaveid;
    args->epfd = epfd;
    args->maxevents = (int)maxevents;

    // We lose the wait thread when we exit the func, but the thread will die
    // on its own copy args then spawn pthread to do the waiting. That way we
    // can ecall with notification. the thread args are freed by the thread
    // func.
    if (pthread_create(&thread, NULL, epoll_wait_thread, args) < 0)
    {
        _set_err(err, EINVAL);
        goto done;
    }
    ret = 0;
#else
    _set_err(err, 38); // ENOSYS
    ret = -1;
    goto done;
#endif


done:
    return ret;
}

int oe_posix_epoll_ctl_add_ocall(
    int epfd,
    int fd,
    unsigned int event_mask,
    int list_idx,
    int epoll_enclave_fd,
    int* err)
{
    int ret = -1;

#if defined(NOTYET)
    oe_ev_data_t ev_data = {
        .event_list_idx = (uint32_t)list_idx,
        .epoll_enclave_fd = (uint32_t)epoll_enclave_fd,
    };

    struct epoll_event ev = {
        .events = event_mask,
        .data.u64 = ev_data.data,
    };

    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);

    if (ret == -1)
        _set_err(err, errno);
#else
    _set_err(err, 38); // ENOSYS
    ret = -1;
#endif

    return ret;
}

int oe_posix_epoll_ctl_del_ocall(int epfd, int fd, int* err)
{
    int ret = -1; // epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL); 2DO

#if defined(NOTYET)
    if (ret == -1)
        _set_err(err, errno);
#else
    _set_err(err, 38); // ENOSYS
    ret = -1;
#endif

    return ret;
}

int oe_posix_epoll_ctl_mod_ocall(
    int epfd,
    int fd,
    unsigned int event_mask,
    int list_idx,
    int enclave_fd,
    int* err)
{
#if defined(NOTYET)
    oe_ev_data_t ev_data = {
        .event_list_idx = (uint32_t)list_idx,
        .epoll_enclave_fd = (uint32_t)enclave_fd,
    };

    struct epoll_event ev = {
        .events = event_mask,
        .data.u64 = ev_data.data,
    };

    int ret = epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);

    if (ret == -1)
        _set_err(err, errno);
#else
    _set_err(err, 38); // ENOSYS
    int ret = -1;
#endif

    return ret;
}

int oe_posix_epoll_close_ocall(int fd, int* err)
{
    int ret = -1; // close(fd); 2Do

#if defined(NOTYET)
    if (ret == -1)
        _set_err(err, errno);
#else
        _set_err(err, 38); // ENOSYS
#endif
    return ret;
}

/* ATTN:IO: never called. */
int oe_posix_shutdown_polling_device_ocall(int fd, int* err)
{
    OE_UNUSED(fd);
    OE_UNUSED(err);

    if (err)
        *err = 0;

    return 0;
}

int oe_posix_epoll_poll_ocall(
    int64_t enclaveid,
    int epfd,
    struct pollfd* fds,
    size_t nfds,
    int timeout,
    int* err)
{
    int ret = -1;
#if defined(NOTYET)
    size_t fdsize = 0;
    pthread_t thread = 0;
    poll_args_t* args = NULL;
    nfds_t fd_idx = 0;

    (void)timeout;

    /* ATTN:IO: how does this work without using the events parameter. */

    fdsize = sizeof(struct pollfd) * nfds;

    if (!(args = (poll_args_t*)calloc(1, sizeof(*args) + fdsize)))
    {
        _set_err(err, ENOMEM);
        goto done;
    }

    args->enclaveid = enclaveid;
    args->epfd = epfd;
    args->nfds = nfds;
    for (; fd_idx < nfds; fd_idx++)
    {
        args->fds[fd_idx] = fds[fd_idx];
    }

    // We lose the wait thread when we exit the func, but the thread will die
    // on its own copy args then spawn pthread to do the waiting. That way we
    // can ecall with notification. the thread args are freed by the thread
    // func.
    if (pthread_create(&thread, NULL, poll_wait_thread, args) < 0)
    {
        _set_err(err, EINVAL);
        goto done;
    }
#else
    _set_err(err, 38); // ENOSYS
    ret = -1;
    goto done;
#endif

    ret = 0;

done:
    return ret;
}

int oe_posix_getpid(void)
{
#if defined(NOTYET)
    return getpid();
#else
    return -1;
#endif
}

int oe_posix_getppid(void)
{
#if defined(NOTYET)
    return getppid();
#else
    return -1;
#endif
}

int oe_posix_getpgrp(void)
{
#if defined(NOTYET)
    return getpgrp();
#else
    return -1;
#endif
}

unsigned int oe_posix_getuid(void)
{
#if defined(NOTYET)
    return getuid();
#else
    return (unsigned int)-1;
#endif
}

unsigned int oe_posix_geteuid(void)
{
#if defined(NOTYET)
    return geteuid();
#else
    return (unsigned int)-1;
#endif
}

unsigned int oe_posix_getgid(void)
{
#if defined(NOTYET)
    return getgid();
#else
    return (unsigned int)-1;
#endif
}

unsigned int oe_posix_getegid(void)
{
#if defined(NOTYET)
    return getegid();
#else
    return (unsigned int)-1;
#endif
}

int oe_posix_getpgid(int pid, int* err)
{
    int ret;

    _clear_err(err);

#if defined(NOTYET)
    if ((ret = getpgid(pid)) == -1)
        _set_err(err, errno);
#else
    _set_err(err, 38); // ENOSYS
    ret = -1;
#endif

    return ret;
}

int oe_posix_getgroups(size_t size, unsigned int* list, int* err)
{
    int ret = -1;

    _clear_err(err);

    if (size > INT_MAX)
    {
        _set_err(err, EINVAL);
        goto done;
    }

#if defined(NOTYET)
    if ((ret = getgroups((int)size, list)) == -1)
        _set_err(err, errno);
#else
    _set_err(err, 38); // ENOSYS
    ret = -1;
    goto done;
#endif

done:
    return ret;
}
