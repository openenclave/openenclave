// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <openenclave/internal/posix/types.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
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

static void _relocate_iov_bases(
    struct oe_iovec* iov,
    int iovcnt,
    ptrdiff_t addend)
{
    for (int i = 0; i < iovcnt; i++)
    {
        if (iov[i].iov_base)
            iov[i].iov_base = (uint8_t*)iov[i].iov_base + addend;
    }
}

ssize_t oe_posix_readv_ocall(
    oe_host_fd_t fd,
    void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    struct oe_iovec* iov = (struct oe_iovec*)iov_buf;
    ssize_t ret = -1;
    ssize_t size_read;

    OE_UNUSED(iov_buf_size);

    errno = 0;

    if ((!iov_buf && iovcnt) || !iov_buf_size)
    {
        errno = EINVAL;
        goto done;
    }

    _relocate_iov_bases(iov, iovcnt, (ptrdiff_t)iov_buf);

    size_read = readv((int)fd, (struct iovec*)iov, iovcnt);

    _relocate_iov_bases(iov, iovcnt, -(ptrdiff_t)iov_buf);

    ret = size_read;

done:
    return ret;
}

ssize_t oe_posix_writev_ocall(
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    ssize_t ret = -1;
    ssize_t size_written;
    struct oe_iovec* iov = (struct oe_iovec*)iov_buf;

    OE_UNUSED(iov_buf_size);

    errno = 0;

    if ((!iov_buf && iovcnt) || !iov_buf_size)
    {
        errno = EINVAL;
        goto done;
    }

    _relocate_iov_bases(iov, iovcnt, (ptrdiff_t)iov_buf);

    size_written = writev((int)fd, (struct iovec*)iov, iovcnt);

    ret = size_written;

done:
    return ret;
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

int oe_posix_readdir_ocall(uint64_t dirp, struct oe_dirent* entry)
{
    int ret = -1;
    struct dirent* ent;

    errno = 0;

    if (!dirp)
    {
        errno = EBADF;
        goto done;
    }

    if (!entry)
    {
        errno = EINVAL;
        goto done;
    }

    /* Perform the readdir() operation. */
    {
        errno = 0;

        if (!(ent = readdir((DIR*)dirp)))
        {
            if (errno)
                goto done;

            ret = 1;
            goto done;
        }
    }

    /* Copy the local entry to the caller's entry structure. */
    {
        size_t len = strlen(ent->d_name);

        entry->d_ino = ent->d_ino;
        entry->d_off = ent->d_off;
        entry->d_type = ent->d_type;
        entry->d_reclen = sizeof(struct oe_dirent);

        if (len >= sizeof(entry->d_name))
        {
            errno = ENAMETOOLONG;
            goto done;
        }

        memcpy(entry->d_name, ent->d_name, len + 1);
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

int oe_posix_ioctl_ocall(oe_host_fd_t fd, uint64_t request, uint64_t arg)
{
    errno = 0;

    return ioctl((int)fd, request, arg);
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

int oe_posix_getaddrinfo_open_ocall(
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    uint64_t* handle_out)
{
    int ret = EAI_FAIL;
    getaddrinfo_handle_t* handle = NULL;

    errno = 0;

    if (handle_out)
        *handle_out = 0;

    if (!handle_out)
    {
        ret = EAI_SYSTEM;
        errno = EINVAL;
        goto done;
    }

    if (!(handle = calloc(1, sizeof(getaddrinfo_handle_t))))
    {
        ret = EAI_MEMORY;
        goto done;
    }

    ret =
        getaddrinfo(node, service, (const struct addrinfo*)hints, &handle->res);

    if (ret == 0)
    {
        handle->magic = GETADDRINFO_HANDLE_MAGIC;
        handle->next = handle->res;
        *handle_out = (uint64_t)handle;
        handle = NULL;
    }

done:

    if (handle)
        free(handle);

    return ret;
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

/*
**==============================================================================
**
** epoll:
**
**==============================================================================
*/

#define MAX_EPOLLS 64
#define WAKEFD_MAGIC 0x8700666859244b71

typedef struct _epoll
{
    int epfd;
    int wakefds[2];
} epoll_t;

static epoll_t _epolls[MAX_EPOLLS];
static size_t _num_epolls;
static pthread_spinlock_t _epolls_lock;
static pthread_once_t _epolls_once = PTHREAD_ONCE_INIT;

static void _init_epolls_lock(void)
{
    pthread_spin_init(&_epolls_lock, PTHREAD_PROCESS_PRIVATE);
}

oe_host_fd_t oe_posix_epoll_create1_ocall(int flags)
{
    int ret = -1;
    int epfd = -1;
    int wakefds[2] = {-1, -1};
    errno = 0;

    pthread_once(&_epolls_once, _init_epolls_lock);

    if ((epfd = epoll_create1(flags)) == -1)
        goto done;

    if (pipe(wakefds) == -1)
        goto done;

    /* Watch for events on the wake file descriptor. */
    {
        struct epoll_event event;

        memset(&event, 0, sizeof(event));
        event.events = EPOLLIN;
        event.data.u64 = WAKEFD_MAGIC;

        if ((epoll_ctl(epfd, EPOLL_CTL_ADD, wakefds[0], &event)) == -1)
            goto done;
    }

    /* Inject entry for this epoll into the epolls array. */
    {
        pthread_spin_lock(&_epolls_lock);

        if (_num_epolls == MAX_EPOLLS)
        {
            errno = ENOMEM;
            pthread_spin_unlock(&_epolls_lock);
            goto done;
        }

        _epolls[_num_epolls].epfd = epfd;
        _epolls[_num_epolls].wakefds[0] = wakefds[0];
        _epolls[_num_epolls].wakefds[1] = wakefds[1];
        _num_epolls++;

        pthread_spin_unlock(&_epolls_lock);
    }

    ret = epfd;
    epfd = -1;
    wakefds[0] = -1;
    wakefds[1] = -1;

done:

    if (epfd != -1)
        close(epfd);

    if (wakefds[0] != -1)
        close(wakefds[0]);

    if (wakefds[1] != -1)
        close(wakefds[1]);

    return ret;
}

int oe_posix_epoll_wait_ocall(
    int64_t epfd,
    struct oe_epoll_event* events,
    unsigned int maxevents,
    int timeout)
{
    int ret = -1;
    int nfds;
    bool found_wake_event = false;

    pthread_once(&_epolls_once, _init_epolls_lock);

    errno = 0;

    nfds = epoll_wait(
        (int)epfd, (struct epoll_event*)events, (int)maxevents, timeout);

    if (nfds < 0)
        goto done;

    /* Remove the dummy event for the wakefd. */
    for (int i = 0; i < nfds; i++)
    {
        if (events[i].data.u64 == WAKEFD_MAGIC)
        {
            events[i] = events[nfds - 1];
            nfds--;
            found_wake_event = true;
            break;
        }
    }

    /* Read the word that oe_posix_epoll_wake_ocall() wrote. */
    if (found_wake_event)
    {
        int fd = -1;
        uint64_t c;

        /* Find the read descriptor for the wakefds[] pipe. */
        {
            pthread_spin_lock(&_epolls_lock);

            for (size_t i = 0; i < _num_epolls; i++)
            {
                if (_epolls[i].epfd == epfd)
                {
                    fd = _epolls[i].wakefds[0];
                    break;
                }
            }

            pthread_spin_unlock(&_epolls_lock);
        }

        if (fd == -1)
        {
            errno = EINVAL;
            goto done;
        }

        if (read(fd, &c, sizeof(c)) != sizeof(c) || c != WAKEFD_MAGIC)
        {
            goto done;
        }

        /* Treat as an interrupt if no other descriptors are read. */
        if (nfds == 0)
        {
            errno = EINTR;
            goto done;
        }
    }

    ret = nfds;

done:

    return ret;
}

int oe_posix_epoll_wake_ocall(void)
{
    int ret = -1;
    int fd = -1;

    pthread_once(&_epolls_once, _init_epolls_lock);

    /* Find the write end of the wake pipe. */
    {
        pthread_spin_lock(&_epolls_lock);

        for (size_t i = 0; i < _num_epolls; i++)
        {
            fd = _epolls[i].wakefds[1];
            break;
        }

        pthread_spin_unlock(&_epolls_lock);
    }

    if (fd != -1)
    {
        const uint64_t c = WAKEFD_MAGIC;

        if (write(fd, &c, sizeof(c)) != sizeof(c))
            goto done;
    }

    ret = 0;

done:
    return ret;
}

int oe_posix_epoll_ctl_ocall(
    int64_t epfd,
    int op,
    int64_t fd,
    struct oe_epoll_event* event)
{
    errno = 0;

    return epoll_ctl((int)epfd, op, (int)fd, (struct epoll_event*)event);
}

int oe_posix_epoll_close_ocall(oe_host_fd_t epfd)
{
    int fd0 = -1;
    int fd1 = -1;
    errno = 0;

    pthread_once(&_epolls_once, _init_epolls_lock);

    /* Close both ends of the wakefd pipe and remove the epoll_t struct. */
    {
        pthread_spin_lock(&_epolls_lock);

        for (size_t i = 0; i < _num_epolls; i++)
        {
            if (_epolls[i].epfd == epfd)
            {
                fd0 = _epolls[i].wakefds[0];
                fd1 = _epolls[i].wakefds[1];
                _epolls[i] = _epolls[_num_epolls - 1];
                _num_epolls--;
                break;
            }
        }

        pthread_spin_unlock(&_epolls_lock);
    }

    if (fd0 != -1)
        close(fd0);

    if (fd1 != -1)
        close(fd1);

    return close((int)epfd);
}

int oe_posix_shutdown_polling_device_ocall(oe_host_fd_t fd)
{
    OE_UNUSED(fd);

    errno = 0;

    return 0;
}

/*
**==============================================================================
**
** poll:
**
**==============================================================================
*/

int oe_posix_poll_ocall(
    struct oe_host_pollfd* host_fds,
    oe_nfds_t nfds,
    int timeout)
{
    int ret = -1;
    struct oe_pollfd* fds = NULL;

    errno = 0;

    if (nfds == 0)
    {
        errno = EINVAL;
        goto done;
    }

    if (!(fds = calloc(nfds, sizeof(struct oe_pollfd))))
    {
        errno = ENOMEM;
        goto done;
    }

    /* Convert host_fds[] array to fds[] array. */
    for (oe_nfds_t i = 0; i < nfds; i++)
    {
        fds[i].events = host_fds[i].events;
        fds[i].fd = (int)host_fds[i].fd;
    }

    if ((ret = poll((struct pollfd*)fds, nfds, timeout)) <= 0)
        goto done;

    /* Update the revents in the fds[] array. */
    for (oe_nfds_t i = 0; i < nfds; i++)
    {
        host_fds[i].revents = fds[i].revents;
    }

done:

    if (fds)
        free(fds);

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
        /* sysname: */
        {
            if (strlen(uts.sysname) >= sizeof(buf->sysname))
            {
                errno = ENAMETOOLONG;
                goto done;
            }

            strcpy(buf->sysname, uts.sysname);
        }

        /* nodename: */
        {
            if (strlen(uts.nodename) >= sizeof(buf->nodename))
            {
                errno = ENAMETOOLONG;
                goto done;
            }

            strcpy(buf->nodename, uts.nodename);
        }

        /* release: */
        {
            if (strlen(uts.release) >= sizeof(buf->release))
            {
                errno = ENAMETOOLONG;
                goto done;
            }

            strcpy(buf->release, uts.release);
        }

        /* version: */
        {
            if (strlen(uts.version) >= sizeof(buf->version))
            {
                errno = ENAMETOOLONG;
                goto done;
            }

            strcpy(buf->version, uts.version);
        }

        /* machine: */
        {
            if (strlen(uts.machine) >= sizeof(buf->machine))
            {
                errno = ENAMETOOLONG;
                goto done;
            }

            strcpy(buf->machine, uts.machine);
        }

        /* domainname: */
        {
            if (strlen(uts.domainname) >= sizeof(buf->domainname))
            {
                errno = ENAMETOOLONG;
                goto done;
            }

            strcpy(buf->domainname, uts.domainname);
        }
    }

done:
    return ret;
}
