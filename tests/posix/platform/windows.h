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
//
#include <stdio.h>

typedef SOCKET socket_t;
typedef int socklen_t;
typedef int length_t;
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

OE_INLINE ssize_t
sock_send(socket_t sockfd, const void* buf, size_t len, int flags)
{
    return send(sockfd, (const char*)buf, (int)len, flags);
}

OE_INLINE ssize_t sock_recv(socket_t sockfd, void* buf, size_t len, int flags)
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
    OE_UNUSED(nfds);
    return select(0, readfds, writefds, exceptfds, timeout);
}

OE_INLINE int get_error(void)
{
    return WSAGetLastError();
}

typedef struct _thread
{
    HANDLE __impl;
} thread_t;

typedef struct _thread_proc_param
{
    void* (*start_routine)(void*);
    void* arg;
} thread_proc_param_t;

static DWORD _thread_proc(void* param_)
{
    thread_proc_param_t* param = (thread_proc_param_t*)param_;

    (*param->start_routine)(param->arg);

    free(param);

    return 0;
}

OE_INLINE int thread_create(
    thread_t* thread,
    void* (*start_routine)(void*),
    void* arg)
{
    HANDLE handle;
    thread_proc_param_t* param;

    if (!(param = (thread_proc_param_t*)calloc(1, sizeof(thread_proc_param_t))))
        return -1;

    param->start_routine = start_routine;
    param->arg = arg;

    handle = CreateThread(NULL, 0, _thread_proc, param, 0, NULL);

    if (handle == INVALID_HANDLE_VALUE)
        return -1;

    thread->__impl = handle;
    return 0;
}

OE_INLINE int thread_join(thread_t thread)
{
    if (WaitForSingleObject(thread.__impl, INFINITE) == WAIT_OBJECT_0)
        return 0;

    return -1;
}

OE_INLINE void sleep_msec(uint32_t msec)
{
    Sleep(msec);
}

OE_INLINE bool test_would_block()
{
    return WSAGetLastError() == WSAEWOULDBLOCK;
}

#endif /* _PLATFORM_WINDOWS_H */
