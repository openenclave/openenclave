// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_TEST_POLLING_INTERFACE_H
#define _OE_TEST_POLLING_INTERFACE_H

#include <arpa/inet.h>
#include <openenclave/corelibc/arpa/inet.h>
#include <openenclave/corelibc/fcntl.h>
#include <openenclave/corelibc/poll.h>
#include <openenclave/corelibc/sys/epoll.h>
#include <openenclave/corelibc/sys/select.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/defs.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

struct corelibc
{
    typedef struct oe_sockaddr_in SOCKADDR_IN_T;
    typedef struct oe_sockaddr SOCKADDR_T;
    typedef struct oe_epoll_event EPOLL_EVENT_T;
    static const int AF_INET_T = OE_AF_INET;
    static const int SOCK_STREAM_T = OE_SOCK_STREAM;
    static const long INADDR_LOOPBACK_T = OE_INADDR_LOOPBACK;
    static const int O_NONBLOCK_T = OE_O_NONBLOCK;
    static const int O_RDONLY_T = OE_O_RDONLY;
    static const int O_WRONLY_T = OE_O_WRONLY;
    static const int O_CREAT_T = OE_O_CREAT;
    static const int O_TRUNC_T = OE_O_TRUNC;
    enum
    {
        EPOLLIN_T = OE_EPOLLIN
    };
    enum
    {
        EPOLL_CTL_ADD_T = OE_EPOLL_CTL_ADD
    };
    enum
    {
        EPOLL_CTL_DEL_T = OE_EPOLL_CTL_DEL
    };
    enum
    {
        EPOLL_CTL_MOD_T = OE_EPOLL_CTL_MOD
    };
    typedef oe_fd_set FD_SET_T;
    typedef struct oe_timeval TIMEVAL_T;
    typedef struct oe_pollfd POLLFD_T;

    ssize_t read(int fd, void* buf, size_t count)
    {
        return ::oe_read(fd, buf, count);
    }

    ssize_t write(int fd, const void* buf, size_t count)
    {
        return ::oe_write(fd, buf, count);
    }

    int epoll_create1(int flags)
    {
        return ::oe_epoll_create1(flags);
    }

    int socket(int domain, int type, int protocol)
    {
        return ::oe_socket(domain, type, protocol);
    }

    uint32_t htonl(uint32_t hostlong)
    {
        return ::oe_htonl(hostlong);
    }

    uint16_t htons(uint16_t hostshort)
    {
        return ::oe_htons(hostshort);
    }

    int connect(int sockfd, const SOCKADDR_T* addr, socklen_t addrlen)
    {
        return ::oe_connect(sockfd, addr, addrlen);
    }

    int close(int fd)
    {
        return ::oe_close(fd);
    }

    int epoll_ctl(int epfd, int op, int fd, EPOLL_EVENT_T* event)
    {
        return ::oe_epoll_ctl(epfd, op, fd, event);
    }

    int epoll_wait(int epfd, EPOLL_EVENT_T* events, int maxevents, int timeout)
    {
        return ::oe_epoll_wait(epfd, events, maxevents, timeout);
    }

    int open(const char* pathname, int flags, mode_t mode)
    {
        return ::oe_open(pathname, flags, mode);
    }

    int select(
        int nfds,
        FD_SET_T* readfds,
        FD_SET_T* writefds,
        FD_SET_T* exceptfds,
        TIMEVAL_T* timeout)
    {
        return ::oe_select(nfds, readfds, writefds, exceptfds, timeout);
    }

    void FD_ZERO_F(FD_SET_T* set)
    {
        OE_FD_ZERO(set);
    }

    void FD_SET_F(int fd, FD_SET_T* set)
    {
        OE_FD_SET(fd, set);
    }

    int FD_ISSET_F(int fd, FD_SET_T* set)
    {
        return OE_FD_ISSET(fd, set);
    }

    int poll(POLLFD_T* fds, nfds_t nfds, int timeout)
    {
        return ::oe_poll(fds, nfds, timeout);
    }
};

struct libc
{
    typedef struct sockaddr_in SOCKADDR_IN_T;
    typedef struct sockaddr SOCKADDR_T;
    typedef struct epoll_event EPOLL_EVENT_T;
    static const int AF_INET_T = AF_INET;
    static const int SOCK_STREAM_T = SOCK_STREAM;
    static const long INADDR_LOOPBACK_T = INADDR_LOOPBACK;
    static const int O_NONBLOCK_T = O_NONBLOCK;
    static const int O_RDONLY_T = O_RDONLY;
    static const int O_WRONLY_T = O_WRONLY;
    static const int O_CREAT_T = O_CREAT;
    static const int O_TRUNC_T = O_TRUNC;
    enum
    {
        EPOLLIN_T = EPOLLIN
    };
    enum
    {
        EPOLL_CTL_ADD_T = EPOLL_CTL_ADD
    };
    enum
    {
        EPOLL_CTL_DEL_T = EPOLL_CTL_DEL
    };
    enum
    {
        EPOLL_CTL_MOD_T = EPOLL_CTL_MOD
    };
    typedef fd_set FD_SET_T;
    typedef struct timeval TIMEVAL_T;
    typedef struct pollfd POLLFD_T;

    ssize_t read(int fd, void* buf, size_t count)
    {
        return ::read(fd, buf, count);
    }

    ssize_t write(int fd, const void* buf, size_t count)
    {
        return ::write(fd, buf, count);
    }

    int epoll_create1(int flags)
    {
        return ::epoll_create1(flags);
    }

    int socket(int domain, int type, int protocol)
    {
        return ::socket(domain, type, protocol);
    }

    uint32_t htonl(uint32_t hostlong)
    {
        return ::htonl(hostlong);
    }

    uint16_t htons(uint16_t hostshort)
    {
        return ::htons(hostshort);
    }

    int connect(int sockfd, const SOCKADDR_T* addr, socklen_t addrlen)
    {
        return ::connect(sockfd, addr, addrlen);
    }

    int close(int fd)
    {
        return ::close(fd);
    }

    int epoll_ctl(int epfd, int op, int fd, EPOLL_EVENT_T* event)
    {
        return ::epoll_ctl(epfd, op, fd, event);
    }

    int epoll_wait(int epfd, EPOLL_EVENT_T* events, int maxevents, int timeout)
    {
        return ::epoll_wait(epfd, events, maxevents, timeout);
    }

    int open(const char* pathname, int flags, mode_t mode)
    {
        return ::open(pathname, flags, mode);
    }

    int select(
        int nfds,
        FD_SET_T* readfds,
        FD_SET_T* writefds,
        FD_SET_T* exceptfds,
        TIMEVAL_T* timeout)
    {
        return ::select(nfds, readfds, writefds, exceptfds, timeout);
    }

    void FD_ZERO_F(FD_SET_T* set)
    {
        FD_ZERO(set);
    }

    void FD_SET_F(int fd, FD_SET_T* set)
    {
        FD_SET((unsigned long)fd, set);
    }

    int FD_ISSET_F(int fd, FD_SET_T* set)
    {
        return FD_ISSET((unsigned long)fd, set);
    }

    int poll(POLLFD_T* fds, nfds_t nfds, int timeout)
    {
        return ::poll(fds, nfds, timeout);
    }
};

OE_STATIC_ASSERT(
    sizeof(corelibc::SOCKADDR_IN_T) == sizeof(libc::SOCKADDR_IN_T));
OE_STATIC_ASSERT(sizeof(corelibc::SOCKADDR_T) == sizeof(libc::SOCKADDR_T));
OE_STATIC_ASSERT(
    sizeof(corelibc::EPOLL_EVENT_T) == sizeof(libc::EPOLL_EVENT_T));
OE_STATIC_ASSERT(sizeof(corelibc::AF_INET_T) == sizeof(libc::AF_INET_T));
OE_STATIC_ASSERT(
    sizeof(corelibc::SOCK_STREAM_T) == sizeof(libc::SOCK_STREAM_T));
OE_STATIC_ASSERT(
    sizeof(corelibc::INADDR_LOOPBACK_T) == sizeof(libc::INADDR_LOOPBACK_T));
OE_STATIC_ASSERT(sizeof(corelibc::O_NONBLOCK_T) == sizeof(libc::O_NONBLOCK_T));
OE_STATIC_ASSERT(sizeof(corelibc::O_RDONLY_T) == sizeof(libc::O_RDONLY_T));

#endif /* _OE_TEST_POLLING_INTERFACE_H */
