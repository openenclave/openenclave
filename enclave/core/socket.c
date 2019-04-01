// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/internal/device.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/print.h>
// clang-format on

#define printf oe_host_printf

static uint64_t _default_socket_devid = OE_DEVID_NULL;
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

    /* Resolve the device id. */
    if (devid == OE_DEVID_NULL)
    {
        switch (domain)
        {
            case OE_AF_ENCLAVE:
                devid = OE_DEVID_ENCLAVE_SOCKET;
                break;

            case OE_AF_HOST:
                devid = OE_DEVID_HOST_SOCKET;
                break;

            default:
            {
                oe_errno = EINVAL;
                goto done;
            }
        }
    }

    if (!(device = oe_get_devid_device(devid)))
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (!device->ops.socket || !device->ops.socket->socket)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (!(sock = (*device->ops.socket->socket)(device, domain, type, protocol)))
    {
        goto done;
    }

    if ((sd = oe_assign_fd_device(sock)) == -1)
    {
        (*device->ops.socket->base.close)(sock);
        goto done;
    }

    ret = sd;

done:
    return ret;
}

int oe_socketpair(int domain, int type, int protocol, int retfd[2])
{
    ssize_t ret = -1;
    oe_device_t* socks[2] = {0};
    oe_device_t* device;
    uint64_t devid = OE_DEVID_NULL;

    /* Resolve the device id. */
    switch (domain)
    {
        case OE_AF_ENCLAVE:
            devid = OE_DEVID_ENCLAVE_SOCKET;
            break;

        case OE_AF_HOST:
            devid = OE_DEVID_HOST_SOCKET;
            break;

        default:
        {
            oe_errno = EINVAL;
            goto done;
        }
    }

    if (!(device = oe_get_devid_device(devid)))
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (!device->ops.socket || !device->ops.socket->socketpair)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (!(ret = (*device->ops.socket->socketpair)(
              device, domain, type, protocol, socks)))
    {
        goto done;
    }

    if ((retfd[0] = oe_assign_fd_device(socks[0])) < 0)
    {
        (*device->ops.socket->base.close)(socks[0]);
        ret = -1;
        goto done;
    }

    if ((retfd[1] = oe_assign_fd_device(socks[1])) < 0)
    {
        (*device->ops.socket->base.close)(socks[1]);
        ret = -1;
        goto done;
    }

done:
    return (int)ret;
}

int oe_socket(int domain, int type, int protocol)
{
    uint64_t devid = oe_get_default_socket_devid();
    return oe_socket_d(devid, domain, type, protocol);
}

int oe_connect(int sockfd, const struct oe_sockaddr* addr, socklen_t addrlen)

{
    int rtnval = -1;
    oe_device_t* psock = oe_get_fd_device(sockfd);
    if (!psock)
    {
        // Log error here
        return -1; // erno is already set
    }

    if (psock->ops.socket->connect == NULL)
    {
        oe_errno = EINVAL;
        return -1;
    }

    rtnval = (*psock->ops.socket->connect)(psock, addr, addrlen);
    if (rtnval < 0)
    {
        return -1;
    }

    return rtnval;
}

int oe_accept(int sockfd, struct oe_sockaddr* addr, socklen_t* addrlen)

{
    oe_device_t* psock = oe_get_fd_device(sockfd);
    oe_device_t* pnewsock = NULL;
    int newfd = -1;
    if (!psock)
    {
        // Log error here
        return -1; // erno is already set
    }

    if (psock->ops.socket->accept == NULL)
    {
        oe_errno = EINVAL;
        return -1;
    }

    // Create new file descriptor
    (void)(*psock->ops.base->clone)(psock, &pnewsock);

    if ((*pnewsock->ops.socket->accept)(pnewsock, addr, addrlen) < 0)
    {
        oe_free(pnewsock);
        return -1;
    }

    newfd = oe_assign_fd_device(pnewsock);
    if (newfd == -1)
    {
        /* ATTN: check value of newfd here. */
    }

    return newfd;
}

int oe_listen(int sockfd, int backlog)

{
    oe_device_t* psock = oe_get_fd_device(sockfd);

    if (!psock)
    {
        // Log error here
        return -1; // erno is already set
    }

    if (psock->ops.socket->listen == NULL)
    {
        oe_errno = EINVAL;
        return -1;
    }

    // The action routine sets errno
    return (*psock->ops.socket->listen)(psock, backlog);
}

ssize_t oe_recv(int sockfd, void* buf, size_t len, int flags)

{
    oe_device_t* psock = oe_get_fd_device(sockfd);

    if (!psock)
    {
        // Log error here
        return -1; // erno is already set
    }

    if (psock->ops.socket->recv == NULL)
    {
        oe_errno = EINVAL;
        return -1;
    }

    // The action routine sets errno
    return (*psock->ops.socket->recv)(psock, buf, len, flags);
}

ssize_t oe_recvfrom(
    int sockfd,
    void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* src_addr,
    socklen_t* addrlen)
{
    oe_device_t* psock = oe_get_fd_device(sockfd);

    if (!psock)
    {
        // Log error here
        return -1; // erno is already set
    }

    if (psock->ops.socket->recvfrom == NULL)
    {
        oe_errno = EINVAL;
        return -1;
    }

    // The action routine sets errno
    return (*psock->ops.socket->recvfrom)(
        psock, buf, len, flags, src_addr, addrlen);
}

ssize_t oe_send(int sockfd, const void* buf, size_t len, int flags)

{
    oe_device_t* psock = oe_get_fd_device(sockfd);

    if (!psock)
    {
        // Log error here
        return -1; // erno is already set
    }

    if (psock->ops.socket->send == NULL)
    {
        oe_errno = EINVAL;
        return -1;
    }

    // The action routine sets errno
    return (*psock->ops.socket->send)(psock, buf, len, flags);
}

ssize_t oe_sendto(
    int sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* dest_addr,
    socklen_t addrlen)
{
    oe_device_t* psock = oe_get_fd_device(sockfd);

    if (!psock)
    {
        // Log error here
        return -1; // erno is already set
    }

    if (psock->ops.socket->sendto == NULL)
    {
        oe_errno = EINVAL;
        return -1;
    }

    // The action routine sets errno
    return (*psock->ops.socket->sendto)(
        psock, buf, len, flags, dest_addr, addrlen);
}

ssize_t oe_recvmsg(int sockfd, struct oe_msghdr* buf, int flags)

{
    oe_device_t* psock = oe_get_fd_device(sockfd);

    if (!psock)
    {
        // Log error here
        return -1; // erno is already set
    }

    if (psock->ops.socket->recvmsg == NULL)
    {
        oe_errno = EINVAL;
        return -1;
    }

    // The action routine sets errno
    return (*psock->ops.socket->recvmsg)(psock, buf, flags);
}

ssize_t oe_sendmsg(int sockfd, const struct oe_msghdr* buf, int flags)

{
    oe_device_t* psock = oe_get_fd_device(sockfd);

    if (!psock)
    {
        // Log error here
        return -1; // erno is already set
    }

    if (psock->ops.socket->sendmsg == NULL)
    {
        oe_errno = EINVAL;
        return -1;
    }

    // The action routine sets errno
    return (*psock->ops.socket->sendmsg)(psock, buf, flags);
}

int oe_shutdown(int sockfd, int how)

{
    oe_device_t* psock = oe_get_fd_device(sockfd);

    if (!psock)
    {
        // Log error here
        return -1; // erno is already set
    }

    if (psock->ops.socket->shutdown == NULL)
    {
        oe_errno = EINVAL;
        return -1;
    }

    // The action routine sets errno
    return (*psock->ops.socket->shutdown)(psock, how);
}

int oe_getsockname(int sockfd, struct oe_sockaddr* addr, socklen_t* addrlen)
{
    oe_device_t* psock = oe_get_fd_device(sockfd);

    if (!psock)
    {
        // Log error here
        return -1; // erno is already set
    }

    if (psock->ops.socket->getsockname == NULL)
    {
        oe_errno = EINVAL;
        return -1;
    }

    // The action routine sets errno
    return (*psock->ops.socket->getsockname)(psock, addr, addrlen);
}

int oe_getpeername(int sockfd, struct oe_sockaddr* addr, socklen_t* addrlen)
{
    oe_device_t* psock = oe_get_fd_device(sockfd);

    if (!psock)
    {
        // Log error here
        return -1; // erno is already set
    }

    if (psock->ops.socket->getpeername == NULL)
    {
        oe_errno = EINVAL;
        return -1;
    }

    // The action routine sets errno
    return (*psock->ops.socket->getsockname)(psock, addr, addrlen);
}

int oe_getsockopt(
    int sockfd,
    int level,
    int optname,
    void* optval,
    socklen_t* optlen)
{
    oe_device_t* psock = oe_get_fd_device(sockfd);

    if (!psock)
    {
        // Log error here
        return -1; // erno is already set
    }

    if (psock->ops.socket->getsockopt == NULL)
    {
        oe_errno = EINVAL;
        return -1;
    }

    // The action routine sets errno
    return (*psock->ops.socket->getsockopt)(
        psock, level, optname, optval, optlen);
}

int oe_setsockopt(
    int sockfd,
    int level,
    int optname,
    const void* optval,
    socklen_t optlen)

{
    oe_device_t* psock = oe_get_fd_device(sockfd);

    if (!psock)
    {
        // Log error here
        return -1; // erno is already set
    }

    if (psock->ops.socket->setsockopt == NULL)
    {
        oe_errno = EINVAL;
        return -1;
    }

    // The action routine sets errno
    return (*psock->ops.socket->setsockopt)(
        psock, level, optname, optval, optlen);
}

int oe_bind(int sockfd, const struct oe_sockaddr* name, socklen_t namelen)

{
    oe_device_t* psock = oe_get_fd_device(sockfd);

    if (!psock)
    {
        // Log error here
        return -1; // erno is already set
    }

    if (psock->ops.socket->bind == NULL)
    {
        oe_errno = EINVAL;
        return -1;
    }

    // The action routine sets errno
    return (*psock->ops.socket->bind)(psock, name, namelen);
}
