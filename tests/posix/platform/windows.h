// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _PLATFORM_WINDOWS_H
#define _PLATFORM_WINDOWS_H

#pragma warning(disable : 4005)

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

// clang-format off
#include <winsock2.h>
#include <windows.h>
// clang-format on

typedef SOCKET socket_t;
typedef int socklen_t;
typedef int length_t;
typedef HANDLE pthread_t;
typedef void pthread_attr_t;

OE_INLINE int sleep(unsigned int seconds)
{
    Sleep(seconds * 1000);
    return 0;
}

OE_INLINE void sock_startup(void)
{
    static WSADATA wsadata = {0};
    WSAStartup(MAKEWORD(2, 2), &wsadata);
}

OE_INLINE void sock_cleanup(void)
{
    WSACleanup();
}

OE_INLINE int sock_set_blocking(socket_t sock, bool blocking)
{
    unsigned long flag = blocking ? 0 : 1;

    if (ioctlsocket(sock, FIONBIO, &flag) != 0)
        return -1;

    return 0;
}

OE_INLINE ssize_t sock_send(int sockfd, const void* buf, size_t len, int flags)
{
    return send(sockfd, (const char*)buf, (int)len, flags);
}

OE_INLINE ssize_t sock_recv(int sockfd, void* buf, size_t len, int flags)
{
    return recv(sockfd, (char*)buf, (int)len, flags);
}

OE_INLINE int sock_close(socket_t sock)
{
    return closesocket(sock);
}

OE_INLINE int sock_select(
    socket_t nfds,
    fd_set* readfds,
    fd_set* writefds,
    fd_set* exceptfds,
    struct timeval* timeout)
{
    return select(nfds, readfds, writefds, exceptfds, timeout);
}

OE_INLINE int get_error(void)
{
    return WSAGetLastError();
}

OE_INLINE int thread_create(
    pthread_t* thread,
    const pthread_attr_t* attr,
    void* (*start_routine)(void*),
    void* arg)
{
    HANDLE handle;

    handle = CreateThread(
        NULL, 0, (LPTHREAD_START_ROUTINE)start_routine, arg, 0, NULL);

    if (handle == INVALID_HANDLE_VALUE)
        return -1;

    *thread = handle;
    return 0;
}

OE_INLINE int thread_join(pthread_t thread, void** retval)
{
    WaitForSingleObject(thread, INFINITE);
    *retval = NULL;
    return 0;
}

OE_INLINE void sleep_msec(uint32_t msec)
{
    Sleep(msec);
}

#endif /* _PLATFORM_WINDOWS_H */
