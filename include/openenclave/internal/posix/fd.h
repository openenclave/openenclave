// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_POSIX_FD_H
#define _OE_POSIX_FD_H
// clang-format off

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/posix/types.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/corelibc/sys/epoll.h>

OE_EXTERNC_BEGIN

typedef enum _oe_fd_type
{
    OE_FD_TYPE_NONE = 0,
    OE_FD_TYPE_ANY,
    OE_FD_TYPE_FILE,
    OE_FD_TYPE_SOCKET,
    OE_FD_TYPE_EPOLL,
    OE_FD_TYPE_EVENTFD,
} oe_fd_type_t;

typedef struct _oe_fd oe_fd_t;

/* Common operations on file-descriptor objects. */
typedef struct _oe_fd_ops
{
    ssize_t (*read)(oe_fd_t* desc, void* buf, size_t count);

    ssize_t (*write)(oe_fd_t* desc, const void* buf, size_t count);

    int (*dup)(oe_fd_t* desc, oe_fd_t** new_fd);

    int (*ioctl)(oe_fd_t* desc, unsigned long request, uint64_t arg);

    int (*fcntl)(oe_fd_t* desc, int cmd, uint64_t arg);

    oe_host_fd_t (*get_host_fd)(oe_fd_t* desc);

    int (*close)(oe_fd_t* desc);

    int (*release)(oe_fd_t* desc);
}
oe_fd_ops_t;

/* File operations. */
typedef struct _oe_file_ops
{
    /* Inherited operations. */
    oe_fd_ops_t fd;

    oe_off_t (*lseek)(oe_fd_t* file, oe_off_t offset, int whence);

    int (*getdents)(oe_fd_t* file, struct oe_dirent* dirp, uint32_t count);
}
oe_file_ops_t;

/* Socket operations .*/
typedef struct _oe_sock_ops
{
    /* Inherited operations. */
    oe_fd_ops_t fd;

    int (*connect)(
        oe_fd_t* sock,
        const struct oe_sockaddr* addr,
        oe_socklen_t addrlen);

    oe_fd_t* (*accept)(
        oe_fd_t* sock,
        struct oe_sockaddr* addr,
        oe_socklen_t* addrlen);

    int (*bind)(
        oe_fd_t* sock,
        const struct oe_sockaddr* addr,
        oe_socklen_t addrlen);

    int (*listen)(
        oe_fd_t* sock,
        int backlog);

    ssize_t (*send)(
        oe_fd_t* sock,
        const void* buf,
        size_t len,
        int flags);

    ssize_t (*recv)(
        oe_fd_t* sock,
        void* buf,
        size_t len,
        int flags);

    ssize_t (*sendto)(
        oe_fd_t* sock,
        const void* buf,
        size_t len,
        int flags,
        const struct oe_sockaddr* dest_addr,
        oe_socklen_t addrlen);

    ssize_t (*recvfrom)(
        oe_fd_t* sock,
        void* buf,
        size_t len,
        int flags,
        const struct oe_sockaddr* src_addr,
        oe_socklen_t* addrlen);

    ssize_t (*sendmsg)(
        oe_fd_t* sock,
        const struct oe_msghdr* msg,
        int flags);

    ssize_t (*recvmsg)(
        oe_fd_t* sock,
        struct oe_msghdr* msg,
        int flags);

    int (*shutdown)(
        oe_fd_t* sock,
        int how);

    int (*getsockopt)(
        oe_fd_t* sock,
        int level,
        int optname,
        void* optval,
        oe_socklen_t* optlen);

    int (*setsockopt)(
        oe_fd_t* sock,
        int level,
        int optname,
        const void* optval,
        oe_socklen_t optlen);

    int (*getpeername)(
        oe_fd_t* sock,
        struct oe_sockaddr* addr,
        oe_socklen_t* addrlen);

    int (*getsockname)(
        oe_fd_t* sock,
        struct oe_sockaddr* addr,
        oe_socklen_t* addrlen);
}
oe_sock_ops_t;

/* epoll operations. */
typedef struct _oe_epoll_ops
{
    /* Inherited operations. */
    oe_fd_ops_t fd;

    int (*epoll_ctl)(
        oe_fd_t* epoll,
        int op,
        int fd,
        struct oe_epoll_event* event);

    int (*epoll_wait)(
        oe_fd_t* epoll,
        struct oe_epoll_event* events,
        int maxevents,
        int timeout);
}
oe_epoll_ops_t;

/* eventfd operations. */
typedef struct _oe_eventfd_ops
{
    /* Inherited operations. */
    oe_fd_ops_t fd;
}
oe_eventfd_ops_t;

struct _oe_fd
{
    oe_fd_type_t type;
    union {
        oe_fd_ops_t fd;
        oe_file_ops_t file;
        oe_sock_ops_t sock;
        oe_epoll_ops_t epoll;
        oe_eventfd_ops_t eventfd;
    } ops;
};

OE_EXTERNC_END

// clang-format on
#endif // _OE_POSIX_FD_H
