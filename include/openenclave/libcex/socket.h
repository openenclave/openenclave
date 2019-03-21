/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef _OE_LIBCEX_SOCKET_H
#define _OE_LIBCEX_SOCKET_H

#include <netdb.h>
#include <netinet/in.h>
#include <openenclave/bits/defs.h>
#include <openenclave/corelibc/netdb.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/libcex/sal.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openenclave/corelibc/sys/ioctl.h>

OE_EXTERNC_BEGIN

OE_INLINE int oe_closesocket(_In_ int s)
{
    return oe_close(s);
}

OE_INLINE int oe_ioctlsocket(int fd, unsigned long request, ...)
{
    oe_va_list ap;
    oe_va_start(ap, request);
    int r = oe_ioctl_va(fd, request, ap);
    oe_va_end(ap);
    return r;
}

OE_INLINE int oe_socket_insecure(
    _In_ int domain,
    _In_ int type,
    _In_ int protocol)
{
    return oe_socket_d(OE_DEVID_HOST_SOCKET, domain, type, protocol);
}

OE_INLINE int oe_socket_secure_hardware(
    _In_ int domain,
    _In_ int type,
    _In_ int protocol)
{
    return oe_socket_d(OE_DEVID_HARDWARE_SECURE_SOCKET, domain, type, protocol);
}

OE_INLINE int oe_socket_default(
    _In_ int domain,
    _In_ int type,
    _In_ int protocol)
{
#ifdef OE_SECURE_POSIX_NETWORK_API
    return oe_socket_secure_hardware(domain, type, protocol);
#else
    return oe_socket_insecure(domain, type, protocol);
#endif
}

#if !defined(OE_NO_POSIX_SOCKET_API)
#define socket oe_socket_default
#endif

OE_EXTERNC_END

#endif /* _OE_LIBCEX_SOCKET_H */
