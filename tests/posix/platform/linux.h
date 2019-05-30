// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _PLATFORM_LINUX_H
#define _PLATFORM_LINUX_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <pthread.h>
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

OE_INLINE ssize_t sock_send(int sockfd, const void* buf, size_t len, int flags)
{
    return send(sockfd, buf, len, flags);
}

OE_INLINE ssize_t sock_recv(int sockfd, void* buf, size_t len, int flags)
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
#if defined(OE_BUILD_ENCLAVE)
    extern int oe_sleep_msec(uint64_t milliseconds);
    oe_sleep_msec(msec);
#else
    struct timespec ts;

    ts.tv_sec = (uint8_t)msec / 1000UL;
    ts.tv_nsec = ((uint8_t)msec % 1000UL) * 1000000UL;

    nanosleep(&ts, NULL);
#endif
}

typedef pthread_t thread_t;

#if !defined(OE_BUILD_ENCLAVE)
OE_INLINE int thread_create(
    thread_t* thread,
    void* (*start_routine)(void*),
    void* arg)
{
    return pthread_create(thread, NULL, start_routine, arg);
}
#endif

#if !defined(OE_BUILD_ENCLAVE)
OE_INLINE int thread_join(thread_t thread, void** retval)
{
    return pthread_join(thread, retval);
}
#endif

#endif /* _PLATFORM_LINUX_H */
