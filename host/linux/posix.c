// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "../host/strings.h"
#include "posix_u.h"

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
    errno = 0;

    return open(pathname, flags, mode);
}

ssize_t oe_posix_read_ocall(oe_host_fd_t fd, void* buf, size_t count)
{
    errno = 0;

    return read((int)fd, buf, count);
}

ssize_t oe_posix_write_ocall(oe_host_fd_t fd, const void* buf, size_t count)
{
    errno = 0;

    return write((int)fd, buf, count);
}

oe_off_t oe_posix_lseek_ocall(oe_host_fd_t fd, oe_off_t offset, int whence)
{
    errno = 0;

    return lseek((int)fd, offset, whence);
}

int oe_posix_close_ocall(oe_host_fd_t fd)
{
    errno = 0;

    return close((int)fd);
}

oe_host_fd_t oe_posix_dup_ocall(oe_host_fd_t oldfd)
{
    errno = 0;

    return dup((int)oldfd);
}

uint64_t oe_posix_opendir_ocall(const char* name)
{
    return (uint64_t)opendir(name);
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
    int ret = -1;
    struct dirent* ent;

    errno = 0;

    if (!dirp)
    {
        errno = EBADF;
        goto done;
    }

    if (!d_ino || !d_off || !d_reclen || !d_type || !d_name)
    {
        errno = EINVAL;
        goto done;
    }

    errno = 0;

    if (!(ent = readdir((DIR*)dirp)))
    {
        if (errno)
            goto done;

        ret = -1;
        goto done;
    }

    {
        size_t len = strlen(ent->d_name);

        *d_ino = ent->d_ino;
        *d_off = ent->d_off;
        *d_reclen = ent->d_reclen;
        *d_type = ent->d_type;

        if (len >= d_namelen)
        {
            errno = ENAMETOOLONG;
            goto done;
        }

        memcpy(d_name, ent->d_name, len + 1);
    }

    ret = 0;

done:
    return ret;
}

void oe_posix_rewinddir_ocall(uint64_t dirp)
{
    if (dirp)
        rewinddir((DIR*)dirp);
}

int oe_posix_closedir_ocall(uint64_t dirp)
{
    errno = 0;

    return closedir((DIR*)dirp);
}

int oe_posix_stat_ocall(const char* pathname, struct oe_stat* buf)
{
    int ret = -1;
    struct stat st;

    errno = 0;

    if (!buf)
        goto done;

    if ((ret = stat(pathname, &st)) == -1)
        goto done;

    buf->st_dev = st.st_dev;
    buf->st_dev = st.st_dev;
    buf->st_ino = st.st_ino;
    buf->st_nlink = st.st_nlink;
    buf->st_mode = st.st_mode;
    buf->st_uid = st.st_uid;
    buf->st_gid = st.st_gid;
    buf->st_rdev = st.st_rdev;
    buf->st_size = st.st_size;
    buf->st_blksize = st.st_blksize;
    buf->st_blocks = st.st_blocks;
    buf->st_atim.tv_sec = st.st_atim.tv_sec;
    buf->st_atim.tv_nsec = st.st_atim.tv_nsec;
    buf->st_mtim.tv_sec = st.st_mtim.tv_sec;
    buf->st_mtim.tv_nsec = st.st_mtim.tv_nsec;
    buf->st_ctim.tv_sec = st.st_ctim.tv_sec;
    buf->st_ctim.tv_nsec = st.st_ctim.tv_nsec;

done:
    return ret;
}

int oe_posix_access_ocall(const char* pathname, int mode)
{
    errno = 0;

    return access(pathname, mode);
}

int oe_posix_link_ocall(const char* oldpath, const char* newpath)
{
    errno = 0;

    return link(oldpath, newpath);
}

int oe_posix_unlink_ocall(const char* pathname)
{
    errno = 0;

    return unlink(pathname);
}

int oe_posix_rename_ocall(const char* oldpath, const char* newpath)
{
    errno = 0;

    return rename(oldpath, newpath);
}

int oe_posix_truncate_ocall(const char* path, oe_off_t length)
{
    errno = 0;

    return truncate(path, length);
}

int oe_posix_mkdir_ocall(const char* pathname, oe_mode_t mode)
{
    errno = 0;

    return mkdir(pathname, mode);
}

int oe_posix_rmdir_ocall(const char* pathname)
{
    errno = 0;

    return rmdir(pathname);
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
    errno = 0;

    return socket(domain, type, protocol);
}

int oe_posix_socketpair_ocall(
    int domain,
    int type,
    int protocol,
    oe_host_fd_t sv_out[2])
{
    int ret;
    int sv[2];

    errno = 0;

    if ((ret = socketpair(domain, type, protocol, sv)) != -1)
    {
        sv_out[0] = sv[0];
        sv_out[1] = sv[1];
    }

    return ret;
}

int oe_posix_connect_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    errno = 0;

    OE_STATIC_ASSERT(sizeof(struct oe_sockaddr) == sizeof(struct sockaddr));

    return connect((int)sockfd, (const struct sockaddr*)addr, addrlen);
}

oe_host_fd_t oe_posix_accept_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    int ret;

    errno = 0;

    if ((ret = accept((int)sockfd, (struct sockaddr*)addr, &addrlen_in)) != -1)
    {
        if (addrlen_out)
            *addrlen_out = addrlen_in;
    }

    return ret;
}

int oe_posix_bind_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    errno = 0;

    return bind((int)sockfd, (const struct sockaddr*)addr, addrlen);
}

int oe_posix_listen_ocall(oe_host_fd_t sockfd, int backlog)
{
    errno = 0;

    return listen((int)sockfd, backlog);
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
    ssize_t ret = -1;
    struct msghdr msg;
    struct iovec iov;

    errno = 0;

    iov.iov_base = msg_buf;
    iov.iov_len = msg_buflen;
    msg.msg_name = msg_name;
    msg.msg_namelen = msg_namelen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = msg_control;
    msg.msg_controllen = msg_controllen;
    msg.msg_flags = 0;

    if ((ret = recvmsg((int)sockfd, &msg, flags)) != -1)
    {
        if (*msg_namelen_out)
            *msg_namelen_out = msg.msg_namelen;

        if (*msg_controllen_out)
            *msg_controllen_out = msg.msg_controllen;
    }

    return ret;
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
    struct msghdr msg;
    struct iovec iov;

    errno = 0;

    iov.iov_base = (void*)msg_buf;
    iov.iov_len = msg_buflen;
    msg.msg_name = (void*)msg_name;
    msg.msg_namelen = msg_namelen;
    msg.msg_iov = (void*)&iov;
    msg.msg_iovlen = 1;
    msg.msg_control = (void*)msg_control;
    msg.msg_controllen = msg_controllen;
    msg.msg_flags = 0;

    return sendmsg((int)sockfd, &msg, flags);
}

ssize_t oe_posix_recv_ocall(
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags)
{
    errno = 0;

    return recv((int)sockfd, buf, len, flags);
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
    ssize_t ret;

    errno = 0;

    ret = recvfrom(
        (int)sockfd, buf, len, flags, (struct sockaddr*)src_addr, &addrlen_in);

    if (ret != -1)
    {
        if (addrlen_out)
            *addrlen_out = addrlen_in;
    }

    return ret;
}

ssize_t oe_posix_send_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags)
{
    errno = 0;

    return send((int)sockfd, buf, len, flags);
}

ssize_t oe_posix_sendto_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen)
{
    errno = 0;

    return sendto(
        (int)sockfd,
        buf,
        len,
        flags,
        (const struct sockaddr*)src_addr,
        addrlen);
}

int oe_posix_shutdown_ocall(oe_host_fd_t sockfd, int how)
{
    errno = 0;

    return shutdown((int)sockfd, how);
}

int oe_posix_fcntl_ocall(oe_host_fd_t fd, int cmd, uint64_t arg)
{
    errno = 0;

    return fcntl((int)fd, cmd, arg);
}

int oe_posix_setsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    const void* optval,
    oe_socklen_t optlen)
{
    errno = 0;

    return setsockopt((int)sockfd, level, optname, optval, optlen);
}

int oe_posix_getsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    void* optval,
    oe_socklen_t optlen_in,
    oe_socklen_t* optlen_out)
{
    int ret;

    errno = 0;

    ret = getsockopt((int)sockfd, level, optname, optval, &optlen_in);

    if (ret != -1)
    {
        if (optlen_out)
            *optlen_out = optlen_in;
    }

    return ret;
}

int oe_posix_getsockname_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    int ret;

    errno = 0;

    ret = getsockname((int)sockfd, (struct sockaddr*)addr, &addrlen_in);

    if (ret != -1)
    {
        if (addrlen_out)
            *addrlen_out = addrlen_in;
    }

    return ret;
}

int oe_posix_getpeername_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    int ret;

    errno = 0;

    ret = getpeername((int)sockfd, (struct sockaddr*)addr, &addrlen_in);

    if (ret != -1)
    {
        if (addrlen_out)
            *addrlen_out = addrlen_in;
    }

    return ret;
}

int oe_posix_shutdown_sockets_device_ocall(oe_host_fd_t sockfd)
{
    OE_UNUSED(sockfd);

    errno = 0;

    /* No shutdown actions needed for this device. */

    return 0;
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
    errno = 0;

    return kill(pid, signum);
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
    const struct oe_addrinfo* hints)
{
    getaddrinfo_handle_t* ret = NULL;
    getaddrinfo_handle_t* handle = NULL;

    errno = 0;

    if (!(handle = calloc(1, sizeof(getaddrinfo_handle_t))))
    {
        errno = ENOMEM;
        goto done;
    }

    if (getaddrinfo(
            node, service, (const struct addrinfo*)hints, &handle->res) != 0)
    {
        goto done;
    }

    handle->magic = GETADDRINFO_HANDLE_MAGIC;
    handle->next = handle->res;
    ret = handle;
    handle = NULL;

done:

    if (handle)
        free(handle);

    return (uint64_t)ret;
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
    int ret = -1;
    getaddrinfo_handle_t* handle = _cast_getaddrinfo_handle((void*)handle_);

    errno = 0;

    if (!handle || !ai_flags || !ai_family || !ai_socktype || !ai_protocol ||
        !ai_addrlen || !ai_canonnamelen)
    {
        errno = EINVAL;
        goto done;
    }

    if (!ai_addr && ai_addrlen_in)
    {
        errno = EINVAL;
        goto done;
    }

    if (!ai_canonname && ai_canonnamelen_in)
    {
        errno = EINVAL;
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
            errno = ENAMETOOLONG;
            goto done;
        }

        if (*ai_canonnamelen > ai_canonnamelen_in)
        {
            errno = ENAMETOOLONG;
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

done:
    return ret;
}

int oe_posix_getaddrinfo_close_ocall(uint64_t handle_)
{
    int ret = -1;
    getaddrinfo_handle_t* handle = _cast_getaddrinfo_handle((void*)handle_);

    errno = 0;

    if (!handle)
    {
        errno = EINVAL;
        goto done;
    }

    freeaddrinfo(handle->res);
    free(handle);

    ret = 0;

done:
    return ret;
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
    errno = 0;

    return getnameinfo(
        (const struct sockaddr*)sa, salen, host, hostlen, serv, servlen, flags);
}

int oe_posix_shutdown_resolver_device_ocall(void)
{
    /* No shutdown actions needed for this device. */
    errno = 0;

    return 0;
}

/*
**==============================================================================
**
** Polling:
**
**==============================================================================
*/

typedef struct _wait_args
{
    int64_t enclaveid;
    oe_host_fd_t epfd;
    int maxevents;
    struct epoll_event events[];
} wait_args_t;

static void* _epoll_wait_thread(void* arg_)
{
    int ret;
    wait_args_t* args = (wait_args_t*)arg_;
    int retval;

    ret = epoll_wait((int)args->epfd, args->events, args->maxevents, -1);

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

done:
    free(args);
    return NULL;
}

typedef struct _poll_args
{
    int64_t enclaveid;
    oe_host_fd_t epfd;
    nfds_t nfds;
    struct pollfd fds[];
} poll_args_t;

static void* _poll_wait_thread(void* arg_)
{
    int ret;
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
                notifications[notify_idx].events = (uint32_t)ev[ev_idx].revents;
                notifications[notify_idx].data.list_idx = (uint32_t)ev_idx;

                /* ATTN: casting 64-bit fd to 32-bit fd. */
                notifications[notify_idx].data.epoll_fd = (int)args->epfd;
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

oe_host_fd_t oe_posix_epoll_create1_ocall(int flags)
{
    errno = 0;

    return epoll_create1(flags);
}

int oe_posix_epoll_wait_async_ocall(
    int64_t enclaveid,
    oe_host_fd_t epfd,
    size_t maxevents)
{
    int ret = -1;
    size_t eventsize;
    pthread_t thread = 0;
    wait_args_t* args = NULL;

    eventsize = sizeof(struct oe_epoll_event) * maxevents;

    if (!(args = calloc(1, sizeof(wait_args_t) + eventsize)))
    {
        errno = ENOMEM;
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
        errno = EINVAL;
        goto done;
    }

    ret = 0;

done:
    return ret;
}

int oe_posix_epoll_ctl_add_ocall(
    oe_host_fd_t epfd,
    oe_host_fd_t fd,
    unsigned int event_mask,
    int list_idx,
    int epoll_enclave_fd)
{
    oe_ev_data_t ev_data = {
        .event_list_idx = (uint32_t)list_idx,
        .epoll_enclave_fd = (uint32_t)epoll_enclave_fd,
    };
    struct epoll_event ev = {
        .events = event_mask,
        .data.u64 = ev_data.data,
    };

    errno = 0;

    return epoll_ctl((int)epfd, EPOLL_CTL_ADD, (int)fd, &ev);
}

int oe_posix_epoll_ctl_del_ocall(oe_host_fd_t epfd, oe_host_fd_t fd)
{
    errno = 0;

    return epoll_ctl((int)epfd, EPOLL_CTL_DEL, (int)fd, NULL);
}

int oe_posix_epoll_ctl_mod_ocall(
    oe_host_fd_t epfd,
    oe_host_fd_t fd,
    unsigned int event_mask,
    int list_idx,
    int enclave_fd)
{
    oe_ev_data_t ev_data = {
        .event_list_idx = (uint32_t)list_idx,
        .epoll_enclave_fd = (uint32_t)enclave_fd,
    };
    struct epoll_event ev = {
        .events = event_mask,
        .data.u64 = ev_data.data,
    };

    return epoll_ctl((int)epfd, EPOLL_CTL_MOD, (int)fd, &ev);
}

int oe_posix_epoll_close_ocall(oe_host_fd_t fd)
{
    errno = 0;

    return close((int)fd);
}

int oe_posix_shutdown_polling_device_ocall(oe_host_fd_t fd)
{
    OE_UNUSED(fd);

    errno = 0;

    return 0;
}

int oe_posix_epoll_poll_ocall(
    int64_t enclaveid,
    oe_host_fd_t epfd,
    struct oe_pollfd* fds,
    size_t nfds,
    int timeout)
{
    int ret = -1;
    size_t fdsize = 0;
    pthread_t thread = 0;
    poll_args_t* args = NULL;
    nfds_t fd_idx = 0;

    errno = 0;

    OE_UNUSED(timeout);

    fdsize = sizeof(struct pollfd) * nfds;

    if (!(args = (poll_args_t*)calloc(1, sizeof(*args) + fdsize)))
    {
        errno = ENOMEM;
        goto done;
    }

    args->enclaveid = enclaveid;
    args->epfd = epfd;
    args->nfds = nfds;

    for (; fd_idx < nfds; fd_idx++)
    {
        OE_STATIC_ASSERT(sizeof(args->fds[0]) == sizeof(fds[0]));
        memcpy(&args->fds[fd_idx], &fds[fd_idx], sizeof(fds[fd_idx]));
    }

    // We lose the wait thread when we exit the func, but the thread will die
    // on its own copy args then spawn pthread to do the waiting. That way we
    // can ecall with notification. the thread args are freed by the thread
    // func.
    if (pthread_create(&thread, NULL, poll_wait_thread, args) < 0)
    {
        errno = EINVAL;
        goto done;
    }

    ret = 0;

done:
    return ret;
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
    return getpid();
}

int oe_posix_getppid(void)
{
    return getppid();
}

int oe_posix_getpgrp(void)
{
    return getpgrp();
}

unsigned int oe_posix_getuid(void)
{
    return getuid();
}

unsigned int oe_posix_geteuid(void)
{
    return geteuid();
}

unsigned int oe_posix_getgid(void)
{
    return getgid();
}

unsigned int oe_posix_getegid(void)
{
    return getegid();
}

int oe_posix_getpgid(int pid)
{
    errno = 0;

    return getpgid(pid);
}

int oe_posix_getgroups(size_t size, unsigned int* list)
{
    int ret = -1;

    errno = 0;

    if (size > INT_MAX)
    {
        errno = EINVAL;
        goto done;
    }

    ret = getgroups((int)size, list);

done:
    return ret;
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
    int ret = -1;
    struct utsname uts;

    errno = 0;

    if (buf)
        memset(buf, 0, sizeof(struct oe_utsname));

    if (!buf)
    {
        errno = EINVAL;
        goto done;
    }

    if ((ret = uname(&uts)) != -1)
    {
        oe_strlcpy(buf->sysname, uts.sysname, sizeof(buf->sysname));
        oe_strlcpy(buf->nodename, uts.nodename, sizeof(buf->nodename));
        oe_strlcpy(buf->release, uts.release, sizeof(buf->release));
        oe_strlcpy(buf->version, uts.version, sizeof(buf->version));
        oe_strlcpy(buf->machine, uts.machine, sizeof(buf->machine));
#if defined(_GNU_SOURCE)
        oe_strlcpy(buf->domainname, uts.domainname, sizeof(buf->domainname));
#endif
    }

done:
    return ret;
}
