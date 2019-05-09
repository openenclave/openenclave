// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/internal/posix/device.h>
#include <openenclave/internal/posix/fdtable.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>

static uint64_t _default_socket_devid = OE_DEVID_NONE;
static oe_spinlock_t _default_socket_devid_lock;

void oe_set_default_socket_devid(uint64_t devid)
{
    oe_spin_lock(&_default_socket_devid_lock);
    _default_socket_devid = devid;
    oe_spin_unlock(&_default_socket_devid_lock);
}

uint64_t oe_get_default_socket_devid(void)
{
    oe_spin_lock(&_default_socket_devid_lock);
    uint64_t ret = _default_socket_devid;
    oe_spin_unlock(&_default_socket_devid_lock);
    return ret;
}

int oe_socket_d(uint64_t devid, int domain, int type, int protocol)
{
    int ret = -1;
    int sd;
    oe_device_t* sock = NULL;
    oe_device_t* device;

    if (devid == OE_DEVID_NONE)
    {
        /* Only one device today. */
        devid = OE_DEVID_HOSTSOCK;
    }

    if (!(device = oe_get_device(devid, OE_DEVICE_TYPE_SOCKET)))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!device->ops.socket || !device->ops.socket->socket)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(sock = (*device->ops.socket->socket)(device, domain, type, protocol)))
    {
        OE_RAISE_ERRNO_F(
            oe_errno,
            "devid=%ld domain=%d type=%d protocol=%d",
            devid,
            domain,
            type,
            protocol);
        goto done;
    }

    if ((sd = oe_fdtable_assign(sock)) == -1)
    {
        (*device->ops.socket->base.close)(sock);
        OE_RAISE_ERRNO(oe_errno);
        goto done;
    }

    ret = sd;

done:
    return ret;
}

int oe_socketpair(int domain, int type, int protocol, int retfd[2])
{
    int ret = -1;
    ssize_t retval;
    oe_device_t* socks[2] = {0};
    oe_device_t* device;
    uint64_t devid = OE_DEVID_NONE;

    /* Resolve the device id. */
    switch (domain)
    {
        case OE_AF_ENCLAVE:
            devid = OE_DEVID_ENCLAVESOCK;
            break;

        case OE_AF_HOST:
            devid = OE_DEVID_HOSTSOCK;
            break;

        default:
            OE_RAISE_ERRNO(OE_EINVAL);
    }

    if (!(device = oe_get_device(devid, OE_DEVICE_TYPE_SOCKET)))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!device->ops.socket || !device->ops.socket->socketpair)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(retval = (*device->ops.socket->socketpair)(
              device, domain, type, protocol, socks)))
    {
        OE_RAISE_ERRNO_F(
            OE_EINVAL,
            "retval=%zd devid=%lu, domain=%d type=%d protocol=%d",
            retval,
            devid,
            domain,
            type,
            protocol);
    }

    if ((retfd[0] = oe_fdtable_assign(socks[0])) < 0)
    {
        (*device->ops.socket->base.close)(socks[0]);
        OE_RAISE_ERRNO(oe_errno);
        goto done;
    }

    if ((retfd[1] = oe_fdtable_assign(socks[1])) < 0)
    {
        (*device->ops.socket->base.close)(socks[1]);
        OE_RAISE_ERRNO(oe_errno);
    }

    ret = (int)retval;

done:
    return ret;
}

int oe_socket(int domain, int type, int protocol)
{
    uint64_t devid = oe_get_default_socket_devid();
    return oe_socket_d(devid, domain, type, protocol);
}

int oe_connect(int sockfd, const struct oe_sockaddr* addr, oe_socklen_t addrlen)
{
    int ret = -1;
    oe_device_t* sock;

    if (!(sock = oe_fdtable_get(sockfd, OE_DEVICE_TYPE_SOCKET)))
        OE_RAISE_ERRNO(OE_EBADF);

    if (sock->ops.socket->connect == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = (*sock->ops.socket->connect)(sock, addr, addrlen);

done:
    return ret;
}

int oe_accept(int sockfd, struct oe_sockaddr* addr, oe_socklen_t* addrlen)
{
    oe_device_t* sock;
    oe_device_t* pnewsock = NULL;
    int ret = -1;

    if (!(sock = oe_fdtable_get(sockfd, OE_DEVICE_TYPE_SOCKET)))
        OE_RAISE_ERRNO(OE_EBADF);

    if (sock->ops.socket->accept == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    if ((*sock->ops.base->clone)(sock, &pnewsock) != 0)
        OE_RAISE_ERRNO(OE_EINVAL);

    if ((*pnewsock->ops.socket->accept)(pnewsock, addr, addrlen) < 0)
        OE_RAISE_ERRNO(oe_errno);

    if ((ret = oe_fdtable_assign(pnewsock)) == -1)
        OE_RAISE_ERRNO(oe_errno);

done:
    return ret;
}

int oe_listen(int sockfd, int backlog)
{
    int ret = -1;
    oe_device_t* sock;

    if (!(sock = oe_fdtable_get(sockfd, OE_DEVICE_TYPE_SOCKET)))
        OE_RAISE_ERRNO(OE_EBADFD);

    if (sock->ops.socket->listen == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = (*sock->ops.socket->listen)(sock, backlog);

done:
    return ret;
}

ssize_t oe_recv(int sockfd, void* buf, size_t len, int flags)
{
    ssize_t ret = -1;
    oe_device_t* sock;

    if (!(sock = oe_fdtable_get(sockfd, OE_DEVICE_TYPE_SOCKET)))
        OE_RAISE_ERRNO(OE_EBADFD);

    if (sock->ops.socket->recv == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = (*sock->ops.socket->recv)(sock, buf, len, flags);

done:
    return ret;
}

ssize_t oe_recvfrom(
    int sockfd,
    void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* src_addr,
    oe_socklen_t* addrlen)
{
    ssize_t ret = -1;
    oe_device_t* sock;

    if (!(sock = oe_fdtable_get(sockfd, OE_DEVICE_TYPE_SOCKET)))
        OE_RAISE_ERRNO(OE_EBADFD);

    if (sock->ops.socket->recvfrom == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret =
        (*sock->ops.socket->recvfrom)(sock, buf, len, flags, src_addr, addrlen);

done:
    return ret;
}

ssize_t oe_send(int sockfd, const void* buf, size_t len, int flags)
{
    ssize_t ret = -1;
    oe_device_t* sock;

    if (!(sock = oe_fdtable_get(sockfd, OE_DEVICE_TYPE_SOCKET)))
        OE_RAISE_ERRNO(OE_EBADFD);

    if (sock->ops.socket->send == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = (*sock->ops.socket->send)(sock, buf, len, flags);

done:
    return ret;
}

ssize_t oe_sendto(
    int sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* dest_addr,
    oe_socklen_t addrlen)
{
    ssize_t ret = -1;
    oe_device_t* sock;

    if (!(sock = oe_fdtable_get(sockfd, OE_DEVICE_TYPE_SOCKET)))
        OE_RAISE_ERRNO(OE_EBADFD);

    if (sock->ops.socket->sendto == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret =
        (*sock->ops.socket->sendto)(sock, buf, len, flags, dest_addr, addrlen);

done:
    return ret;
}

ssize_t oe_recvmsg(int sockfd, struct oe_msghdr* buf, int flags)
{
    ssize_t ret = -1;
    oe_device_t* sock;

    if (!(sock = oe_fdtable_get(sockfd, OE_DEVICE_TYPE_SOCKET)))
        OE_RAISE_ERRNO(OE_EBADFD);

    if (sock->ops.socket->recvmsg == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = (*sock->ops.socket->recvmsg)(sock, buf, flags);

done:
    return ret;
}

ssize_t oe_sendmsg(int sockfd, const struct oe_msghdr* buf, int flags)
{
    ssize_t ret = -1;
    oe_device_t* sock;

    if (!(sock = oe_fdtable_get(sockfd, OE_DEVICE_TYPE_SOCKET)))
        OE_RAISE_ERRNO(OE_EBADFD);

    if (sock->ops.socket->sendmsg == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = (*sock->ops.socket->sendmsg)(sock, buf, flags);

done:
    return ret;
}

int oe_shutdown(int sockfd, int how)
{
    int ret = -1;
    oe_device_t* sock;

    if (!(sock = oe_fdtable_get(sockfd, OE_DEVICE_TYPE_SOCKET)))
        OE_RAISE_ERRNO(OE_EBADFD);

    if (sock->ops.socket->shutdown == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = (*sock->ops.socket->shutdown)(sock, how);

done:
    return ret;
}

int oe_getsockname(int sockfd, struct oe_sockaddr* addr, oe_socklen_t* addrlen)
{
    int ret = -1;
    oe_device_t* sock;

    if (!(sock = oe_fdtable_get(sockfd, OE_DEVICE_TYPE_SOCKET)))
        OE_RAISE_ERRNO(OE_EBADFD);

    if (sock->ops.socket->getsockname == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = (*sock->ops.socket->getsockname)(sock, addr, addrlen);

done:
    return ret;
}

int oe_getpeername(int sockfd, struct oe_sockaddr* addr, oe_socklen_t* addrlen)
{
    int ret = -1;
    oe_device_t* sock;

    if (!(sock = oe_fdtable_get(sockfd, OE_DEVICE_TYPE_SOCKET)))
        OE_RAISE_ERRNO(OE_EBADFD);

    if (sock->ops.socket->getpeername == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = (*sock->ops.socket->getsockname)(sock, addr, addrlen);

done:
    return ret;
}

int oe_getsockopt(
    int sockfd,
    int level,
    int optname,
    void* optval,
    oe_socklen_t* optlen)
{
    int ret = -1;
    oe_device_t* sock;

    if (!(sock = oe_fdtable_get(sockfd, OE_DEVICE_TYPE_SOCKET)))
        OE_RAISE_ERRNO(OE_EBADFD);

    if (sock->ops.socket->getsockopt == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = (*sock->ops.socket->getsockopt)(sock, level, optname, optval, optlen);

done:
    return ret;
}

int oe_setsockopt(
    int sockfd,
    int level,
    int optname,
    const void* optval,
    oe_socklen_t optlen)
{
    int ret = -1;
    oe_device_t* sock;

    if (!(sock = oe_fdtable_get(sockfd, OE_DEVICE_TYPE_SOCKET)))
        OE_RAISE_ERRNO(OE_EBADFD);

    if (sock->ops.socket->setsockopt == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = (*sock->ops.socket->setsockopt)(sock, level, optname, optval, optlen);

done:
    return ret;
}

int oe_bind(int sockfd, const struct oe_sockaddr* name, oe_socklen_t namelen)
{
    int ret = -1;
    oe_device_t* sock;

    if (!(sock = oe_fdtable_get(sockfd, OE_DEVICE_TYPE_SOCKET)))
        OE_RAISE_ERRNO(OE_EBADFD);

    if (sock->ops.socket->bind == NULL)
        OE_RAISE_ERRNO(OE_EINVAL);

    ret = (*sock->ops.socket->bind)(sock, name, namelen);

done:
    return ret;
}
