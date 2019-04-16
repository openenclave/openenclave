// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openenclave/internal/fs.h>
#include <openenclave/internal/hostfs.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "oe_u.h"

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

    if (strcmp(pathname, "/dev/stdin") == 0)
    {
        if ((flags & 0x00000003) != OE_O_RDONLY)
        {
            if (err)
                *err = EINVAL;

            goto done;
        }

        ret = OE_STDIN_FILENO;
    }
    else if (strcmp(pathname, "/dev/stdout") == 0)
    {
        if ((flags & 0x00000003) != OE_O_WRONLY)
        {
            if (err)
                *err = EINVAL;

            goto done;
        }

        ret = OE_STDOUT_FILENO;
    }
    else if (strcmp(pathname, "/dev/stderr") == 0)
    {
        if ((flags & 0x00000003) != OE_O_WRONLY)
        {
            if (err)
                *err = EINVAL;

            goto done;
        }

        ret = OE_STDERR_FILENO;
    }
    else
    {
        ret = open(pathname, flags, mode);

        if (ret == -1 && err)
            *err = errno;
    }

done:
    return ret;
}

ssize_t oe_posix_read_ocall(int fd, void* buf, size_t count, int* err)
{
    ssize_t ret = read(fd, buf, count);

    if (ret == -1 && err)
        *err = errno;

    return ret;
}

ssize_t oe_posix_write_ocall(int fd, const void* buf, size_t count, int* err)
{
    ssize_t ret = write(fd, buf, count);

    if (ret == -1 && err)
        *err = errno;

    return ret;
}

off_t oe_posix_lseek_ocall(int fd, off_t offset, int whence, int* err)
{
    off_t ret = lseek(fd, offset, whence);

    if (ret == -1 && err)
        *err = errno;

    return ret;
}

int oe_posix_close_ocall(int fd, int* err)
{
    int ret = close(fd);

    if (ret != 0 && err)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_dup_ocall(int oldfd, int* err)
{
    int ret = dup(oldfd);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

void* oe_posix_opendir_ocall(const char* name, int* err)
{
    void* ret = opendir(name);

    if (!ret && err)
        *err = errno;

    return ret;
}

int oe_posix_readdir_ocall(void* dirp, struct oe_posix_dirent* buf, int* err)
{
    int ret = -1;
    struct dirent* ent = readdir((DIR*)dirp);

    if (err)
        *err = 0;

    if (!buf)
    {
        if (err)
            *err = EBADF;

        goto done;
    }

    if (!ent)
    {
        goto done;
    }

    memset(buf, 0, sizeof(struct oe_posix_dirent));
    buf->d_ino = ent->d_ino;
    buf->d_off = ent->d_off;
    buf->d_reclen = ent->d_reclen;
    buf->d_type = ent->d_type;
    strncat(buf->d_name, ent->d_name, sizeof(buf->d_name) - 1);

    ret = 0;

done:
    return ret;
}

void oe_posix_rewinddir_ocall(void* dirp)
{
    rewinddir((DIR*)dirp);
}

int oe_posix_closedir_ocall(void* dirp, int* err)
{
    int ret = closedir((DIR*)dirp);

    if (ret != 0 && err)
        *err = errno;

    return ret;
}

int oe_posix_stat_ocall(
    const char* pathname,
    struct oe_posix_stat* buf,
    int* err)
{
    struct stat st;
    int ret;

    if (buf)
        memset(buf, 0, sizeof(*buf));

    ret = stat(pathname, &st);

    if (ret == 0)
    {
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
    }
    else
    {
        if (ret != 0 && err)
            *err = errno;
    }

    return ret;
}

int oe_posix_access_ocall(const char* pathname, int mode, int* err)
{
    int ret = access(pathname, mode);

    if (ret != 0 && err)
        *err = errno;

    return ret;
}

int oe_posix_link_ocall(const char* oldpath, const char* newpath, int* err)
{
    int ret = link(oldpath, newpath);

    if (ret != 0 && err)
        *err = errno;

    return ret;
}

int oe_posix_unlink_ocall(const char* pathname, int* err)
{
    int ret = unlink(pathname);

    if (ret != 0 && err)
        *err = errno;

    return ret;
}

int oe_posix_rename_ocall(const char* oldpath, const char* newpath, int* err)
{
    int ret = rename(oldpath, newpath);

    if (ret != 0 && err)
        *err = errno;

    return ret;
}

int oe_posix_truncate_ocall(const char* path, off_t length, int* err)
{
    int ret = truncate(path, length);

    if (ret != 0 && err)
        *err = errno;

    return ret;
}

int oe_posix_mkdir_ocall(const char* pathname, mode_t mode, int* err)
{
    int ret = mkdir(pathname, mode);

    if (ret != 0 && err)
        *err = errno;

    return ret;
}

int oe_posix_rmdir_ocall(const char* pathname, int* err)
{
    int ret = rmdir(pathname);

    if (ret != 0 && err)
        *err = errno;

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
    int ret = socket(domain, type, protocol);

    if (ret == -1 && err)
        *err = errno;

    return ret;
}

int oe_posix_socketpair_ocall(
    int domain,
    int type,
    int protocol,
    int sv[2],
    int* err)
{
    int ret = socketpair(domain, type, protocol, sv);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_connect_ocall(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen,
    int* err)
{
    int ret = connect(sockfd, addr, addrlen);

    if (ret == -1 && err)
        *err = errno;

    return ret;
}

int oe_posix_accept_ocall(
    int sockfd,
    struct sockaddr* addr,
    socklen_t addrlen_in,
    socklen_t* addrlen_out,
    int* err)
{
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
    return ret;
}

int oe_posix_bind_ocall(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen,
    int* err)
{
    int ret = bind(sockfd, addr, addrlen);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_listen_ocall(int sockfd, int backlog, int* err)
{
    errno = 0;

    int ret = listen(sockfd, backlog);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

/* ATTN:IO: need test for this function. */
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

    return ret;
}

/* ATTN:IO: need test for this function. */
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
    ssize_t ret = recv(sockfd, buf, len, flags);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

/* ATTN:IO: need test for this function. */
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
    ssize_t ret = recvfrom(sockfd, buf, len, flags, src_addr, &addrlen_in);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    if (addrlen_out)
        *addrlen_out = addrlen_in;

    return ret;
}

ssize_t oe_posix_send_ocall(
    int sockfd,
    const void* buf,
    size_t len,
    int flags,
    int* err)
{
    ssize_t ret = send(sockfd, buf, len, flags);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

/* ATTN:IO: need test for this function. */
ssize_t oe_posix_sendto_ocall(
    int sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct sockaddr* src_addr,
    socklen_t addrlen,
    int* err)
{
    ssize_t ret = sendto(sockfd, buf, len, flags, src_addr, addrlen);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_shutdown_ocall(int sockfd, int how, int* err)
{
    int ret = shutdown(sockfd, how);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_fcntl_ocall(int fd, int cmd, int arg, int* err)
{
    int ret;

    if (err)
        *err = 0;

    if ((ret = fcntl(fd, cmd, arg)) == -1)
    {
        if (err)
            *err = errno;
    }

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

    ret = setsockopt(sockfd, level, optname, optval, optlen);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

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

    if (optlen)
        *optlen = optlen_in;

    ret = getsockopt(sockfd, level, optname, optval, optlen);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_getsockname_ocall(
    int sockfd,
    struct sockaddr* addr,
    socklen_t addrlen_in,
    socklen_t* addrlen_out,
    int* err)
{
    if (addrlen_out)
        *addrlen_out = addrlen_in;

    int ret = getsockname(sockfd, addr, addrlen_out);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

int oe_posix_getpeername_ocall(
    int sockfd,
    struct sockaddr* addr,
    socklen_t addrlen_in,
    socklen_t* addrlen_out,
    int* err)
{
    if (addrlen_out)
        *addrlen_out = addrlen_in;

    int ret = getpeername(sockfd, addr, addrlen_out);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

/* ATTN:IO: why does this take a sockfd parameter? */
int oe_posix_shutdown_sockets_device_ocall(int sockfd, int* err)
{
    OE_UNUSED(sockfd);
    /* No shutdown actions needed for this device. */
    (void)sockfd;
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

    *err = 0;

    ret = kill(pid, signum);

    if (ret < 0)
    {
        if (err)
            *err = errno;
    }

    return ret;
}

/*
**==============================================================================
**
** Resolver:
**
**==============================================================================
*/

int oe_posix_getaddrinfo_ocall(
    const char* node,
    const char* service,
    const struct addrinfo* hints,
    struct addrinfo** res,
    int* err)
{
    int ret = getaddrinfo(node, service, hints, res);

    if (ret == EAI_SYSTEM)
    {
        if (err)
            *err = errno;

        goto done;
    }

done:
    return ret;
}

void oe_posix_freeaddrinfo_ocall(struct addrinfo* res)
{
    if (res)
        freeaddrinfo(res);
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
    int ret = getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);

    if (ret == EAI_SYSTEM)
    {
        if (err)
            *err = errno;
    }

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
OE_INLINE void _set_err(int* err, int num)
{
    if (err)
        *err = num;
}

int oe_posix_epoll_create1_ocall(int flags, int* err)
{
    int ret = epoll_create1(flags);

    if (ret == -1)
        _set_err(err, errno);

    return ret;
}

int oe_posix_epoll_wait_ocall(
    int64_t enclaveid,
    int epfd,
    struct epoll_event* events,
    size_t maxevents,
    int timeout,
    int* err)
{
    int ret = -1;
    size_t eventsize;
    pthread_t thread = 0;
    wait_args_t* args = NULL;

    (void)events;
    (void)timeout;

    /* ATTN:IO: how does this work without using the events parameter? */

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

    return ret;
}

int oe_posix_epoll_ctl_del_ocall(int epfd, int fd, int* err)
{
    int ret = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);

    if (ret == -1)
        _set_err(err, errno);

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

    return ret;
}

int oe_posix_epoll_close_ocall(int fd, int* err)
{
    int ret = close(fd);

    if (ret == -1)
        _set_err(err, errno);

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

    ret = 0;

done:
    return ret;
}
