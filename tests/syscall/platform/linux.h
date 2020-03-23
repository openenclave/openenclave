// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _PLATFORM_LINUX_H
#define _PLATFORM_LINUX_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define INVALID_SOCKET ((socket_t)-1)

typedef int socket_t;
typedef size_t length_t;

OE_INLINE void sock_startup(void)
{
}

OE_INLINE void sock_cleanup(void)
{
}

OE_INLINE int sock_set_blocking(socket_t sock, bool blocking)
{
    int flags;

    if ((flags = fcntl(sock, F_GETFL, 0)) == -1)
        return -1;

    if (blocking)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;

    if (fcntl(sock, F_SETFL, flags) == -1)
        return -1;

    return 0;
}

OE_INLINE ssize_t
sock_send(socket_t sockfd, const void* buf, size_t len, int flags)
{
    return send(sockfd, buf, len, flags);
}

OE_INLINE ssize_t sock_recv(socket_t sockfd, void* buf, size_t len, int flags)
{
    return recv(sockfd, buf, len, flags);
}

OE_INLINE int sock_close(socket_t sock)
{
    return close(sock);
}

OE_INLINE int sock_select(
    int nfds,
    fd_set* readfds,
    fd_set* writefds,
    fd_set* exceptfds,
    struct timeval* timeout)
{
    return select(nfds, readfds, writefds, exceptfds, timeout);
}

OE_INLINE int get_error(void)
{
    return errno;
}

OE_INLINE void sleep_msec(uint32_t msec)
{
    struct timespec ts;

    ts.tv_sec = (uint64_t)msec / 1000;
    ts.tv_nsec = ((int64_t)msec % 1000) * 1000000;

    nanosleep(&ts, NULL);
}

typedef struct _thread
{
    pthread_t __impl;
} thread_t;

#if !defined(OE_BUILD_ENCLAVE)
OE_INLINE int thread_create(
    thread_t* thread,
    void* (*start_routine)(void*),
    void* arg)
{
    return pthread_create(&thread->__impl, NULL, start_routine, arg);
}
#endif

#if !defined(OE_BUILD_ENCLAVE)
OE_INLINE int thread_join(thread_t thread)
{
    return pthread_join(thread.__impl, NULL);
}
#endif

OE_INLINE bool test_would_block()
{
    return errno == EAGAIN;
}

#endif /* _PLATFORM_LINUX_H */
