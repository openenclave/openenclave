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

OE_INLINE void socket_startup(void)
{
}

OE_INLINE void socket_cleanup(void)
{
}

OE_INLINE int socket_close(socket_t sock)
{
    return close(sock);
}

OE_INLINE int get_error(void)
{
    return errno;
}

#endif /* _PLATFORM_LINUX_H */
