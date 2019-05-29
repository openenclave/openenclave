// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _PLATFORM_WINDOWS_H
#define _PLATFORM_WINDOWS_H

#pragma warning(disable : 4005)

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <windows.h>
#include <winsock2.h>

typedef SOCKET socket_t;
typedef int socklen_t;
typedef int length_t;
typedef HANDLE pthread_t;

OE_INLINE int sleep(unsigned int seconds)
{
    Sleep(n * 1000);
    return 0;
}

OE_INLINE void socket_startup(void)
{
    static WSADATA wsadata = {0};
    WSAStartup(MAKEWORD(2, 2), &wsadata);
}

OE_INLINE void socket_cleanup(void)
{
    WSACleanup();
}

OE_INLINE int socket_close(socket_t sock)
{
    return closesocket(sock);
}

OE_INLINE int get_error(void)
{
    return WSAGetLastError();
}

typedef void pthread_attr_t;

OE_INLINE int pthread_create(
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

OE_INLINE int pthread_join(pthread_t thread, void** retval)
{
    *retval = WaitForSingleObject(client, INFINITE);
    return 0;
}

#endif /* _PLATFORM_WINDOWS_H */
