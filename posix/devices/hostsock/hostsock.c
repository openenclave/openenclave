// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE

// clang-format off
#include <openenclave/enclave.h>
// clang-format on

#include <openenclave/internal/posix/device.h>
#include <openenclave/internal/thread.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/internal/posix/raise.h>
#include <openenclave/internal/posix/iov.h>
#include <openenclave/internal/posix/fd.h>
#include <openenclave/internal/posix/iov.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/raise.h>
#include <openenclave/bits/safecrt.h>
#include "posix_t.h"

#define DEVICE_MAGIC 0x536f636b
#define SOCK_MAGIC 0xe57a696d

static oe_socket_ops_t _get_socket_ops(void);

typedef struct _device
{
    struct _oe_device base;
    uint32_t magic;
    oe_host_fd_t host_fd;
} device_t;

typedef struct _sock
{
    oe_fd_t base;
    uint32_t magic;
    oe_host_fd_t host_fd;
} sock_t;

static sock_t* _new_sock(void)
{
    sock_t* sock = NULL;

    if (!(sock = oe_calloc(1, sizeof(sock_t))))
        return NULL;

    sock->base.type = OE_FD_TYPE_SOCKET;
    sock->base.ops.socket = _get_socket_ops();
    sock->magic = SOCK_MAGIC;
    sock->host_fd = -1;

    return sock;
}

static device_t* _cast_device(const oe_device_t* device)
{
    device_t* p = (device_t*)device;

    if (p == NULL || p->magic != DEVICE_MAGIC)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return p;
}

static sock_t* _cast_sock(const oe_fd_t* desc)
{
    sock_t* sock = (sock_t*)desc;

    if (sock == NULL || sock->magic != SOCK_MAGIC)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return sock;
}

static ssize_t _hostsock_read(oe_fd_t*, void* buf, size_t count);

static int _hostsock_close(oe_fd_t*);

static oe_fd_t* _hostsock_device_socket(
    oe_device_t* dev,
    int domain,
    int type,
    int protocol)
{
    oe_fd_t* ret = NULL;
    device_t* sock = _cast_device(dev);
    sock_t* new_sock = NULL;

    oe_errno = 0;

    if (!sock)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(new_sock = _new_sock()))
        OE_RAISE_ERRNO(OE_ENOMEM);

    /* Call the host. */
    {
        oe_host_fd_t retval = -1;

        if (oe_posix_socket_ocall(&retval, domain, type, protocol) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);

        if (retval == -1)
            OE_RAISE_ERRNO_MSG(oe_errno, "retval=%ld\n", retval);

        new_sock->host_fd = retval;
    }

    ret = &new_sock->base;
    new_sock = NULL;

done:

    if (new_sock)
        oe_free(new_sock);

    return ret;
}

static ssize_t _hostsock_device_socketpair(
    oe_device_t* dev,
    int domain,
    int type,
    int protocol,
    oe_fd_t* sv[2])
{
    int ret = -1;
    device_t* sock = _cast_device(dev);
    sock_t* pair[2] = {NULL, NULL};

    oe_errno = 0;

    if (!sock)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Create the new socket devices. */
    {
        if (!(pair[0] = _new_sock()))
            OE_RAISE_ERRNO(OE_ENOMEM);

        if (!(pair[1] = _new_sock()))
            OE_RAISE_ERRNO(OE_ENOMEM);
    }

    /* Call the host. */
    {
        int retval = -1;
        oe_host_fd_t host_sv[2];

        if (oe_posix_socketpair_ocall(
                &retval, domain, type, protocol, host_sv) != OE_OK)
        {
            OE_RAISE_ERRNO(OE_EINVAL);
        }

        if (retval == -1)
        {
            OE_RAISE_ERRNO_MSG(oe_errno, "retval=%d\n", retval);
        }

        pair[0]->host_fd = host_sv[0];
        pair[1]->host_fd = host_sv[1];
    }

    sv[0] = &pair[0]->base;
    sv[1] = &pair[1]->base;

    ret = 0;
    pair[0] = NULL;
    pair[1] = NULL;

done:

    if (pair[0])
        oe_free(pair[0]);

    if (pair[1])
        oe_free(pair[1]);

    return ret;
}

typedef struct
{
    struct oe_sockaddr addr;
    uint8_t extra[1024];
} sockaddr_t;

static int _hostsock_connect(
    oe_fd_t* sock_,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    sockaddr_t buf;

    oe_errno = 0;

    if (!sock || !addr || sizeof(buf) < addrlen)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_memcpy_s(&buf, sizeof(buf), addr, addrlen) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Call host. */
    if (oe_posix_connect_ocall(&ret, sock->host_fd, &buf.addr, addrlen) !=
        OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

done:
    return ret;
}

static oe_fd_t* _hostsock_accept(
    oe_fd_t* sock_,
    struct oe_sockaddr* addr,
    oe_socklen_t* addrlen)
{
    oe_fd_t* ret = NULL;
    sock_t* sock = _cast_sock(sock_);
    sockaddr_t buf;
    oe_socklen_t addrlen_in = 0;
    sock_t* new_sock = NULL;

    oe_errno = 0;

    if (!sock || (addr && !addrlen) || (addrlen && !addr))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_memset_s(&buf, sizeof(buf), 0, sizeof(buf)) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Fixup the address. */
    if (addr && addrlen)
    {
        if (sizeof(buf) < *addrlen)
            OE_RAISE_ERRNO_MSG(OE_EINVAL, "*addrlen=%u", *addrlen);

        if (oe_memcpy_s(&buf, sizeof(buf), addr, *addrlen) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);

        addrlen_in = *addrlen;
    }

    /* Create the new socket. */
    if (!(new_sock = _new_sock()))
        OE_RAISE_ERRNO(OE_ENOMEM);

    /* Call the host. */
    {
        oe_host_fd_t retval = -1;

        if (oe_posix_accept_ocall(
                &retval, sock->host_fd, &buf.addr, addrlen_in, addrlen) !=
            OE_OK)
        {
            OE_RAISE_ERRNO(oe_errno);
        }

        if (retval == -1)
            OE_RAISE_ERRNO_MSG(oe_errno, "retval=%d", retval);

        new_sock->host_fd = retval;
    }

    ret = &new_sock->base;
    new_sock = NULL;

done:

    if (new_sock)
        oe_free(new_sock);

    return ret;
}

static int _hostsock_bind(
    oe_fd_t* sock_,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    sockaddr_t buf;

    oe_errno = 0;

    if (!sock || !addr || sizeof(buf) < addrlen)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_memcpy_s(&buf, sizeof(buf), addr, addrlen) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Call the host. */
    if (oe_posix_bind_ocall(&ret, sock->host_fd, &buf.addr, addrlen) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:

    return ret;
}

static int _hostsock_listen(oe_fd_t* sock_, int backlog)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_listen_ocall(&ret, sock->host_fd, backlog) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _hostsock_recv(
    oe_fd_t* sock_,
    void* buf,
    size_t count,
    int flags)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock || (count && !buf))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (buf)
    {
        if (oe_memset_s(buf, sizeof(count), 0, sizeof(count)) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);
    }

    if (oe_posix_recv_ocall(&ret, sock->host_fd, buf, count, flags) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _hostsock_recvfrom(
    oe_fd_t* sock_,
    void* buf,
    size_t count,
    int flags,
    const struct oe_sockaddr* src_addr,
    oe_socklen_t* addrlen)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_socklen_t addrlen_in = 0;

    oe_errno = 0;

    if (!sock || (count && !buf))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (addrlen)
        addrlen_in = *addrlen;

    if (oe_posix_recvfrom_ocall(
            &ret,
            sock->host_fd,
            buf,
            count,
            flags,
            (struct oe_sockaddr*)src_addr,
            addrlen_in,
            addrlen) != OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

done:
    return ret;
}

static ssize_t _hostsock_recvmsg(
    oe_fd_t* sock_,
    struct oe_msghdr* msg,
    int flags)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_errno = 0;
    void* buf = NULL;
    size_t buf_size = 0;

    /* Check the parameters. */
    if (!sock || !msg || (msg->msg_iovlen && !msg->msg_iov))
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Flatten the IO vector into contiguous heap memory. */
    if (oe_iov_pack(msg->msg_iov, (int)msg->msg_iovlen, &buf, &buf_size) != 0)
        OE_RAISE_ERRNO(OE_ENOMEM);

    /* Call the host. */
    {
        if (oe_posix_recvmsg_ocall(
                &ret,
                sock->host_fd,
                msg->msg_name,
                msg->msg_namelen,
                &msg->msg_namelen,
                buf,
                msg->msg_iovlen,
                buf_size,
                msg->msg_control,
                msg->msg_controllen,
                &msg->msg_controllen,
                flags) != OE_OK)
        {
            OE_RAISE_ERRNO(OE_EINVAL);
        }

        if (ret == -1)
            OE_RAISE_ERRNO(oe_errno);
    }

    /* Synchronize data read with IO vector. */
    if (oe_iov_sync(msg->msg_iov, (int)msg->msg_iovlen, buf, buf_size) != 0)
        OE_RAISE_ERRNO(OE_EINVAL);

done:

    if (buf)
        oe_free(buf);

    return ret;
}

static ssize_t _hostsock_send(
    oe_fd_t* sock_,
    const void* buf,
    size_t count,
    int flags)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock || (count && !buf))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_send_ocall(&ret, sock->host_fd, buf, count, flags) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _hostsock_sendto(
    oe_fd_t* sock_,
    const void* buf,
    size_t count,
    int flags,
    const struct oe_sockaddr* dest_addr,
    oe_socklen_t addrlen)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock || (count && !buf))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_sendto_ocall(
            &ret,
            sock->host_fd,
            buf,
            count,
            flags,
            (struct oe_sockaddr*)dest_addr,
            addrlen) != OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

done:
    return ret;
}

static ssize_t _hostsock_sendmsg(
    oe_fd_t* sock_,
    const struct oe_msghdr* msg,
    int flags)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    void* buf = NULL;
    size_t buf_size = 0;

    oe_errno = 0;

    /* Check the parameters. */
    if (!sock || !msg || (msg->msg_iovlen && !msg->msg_iov))
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Flatten the IO vector into contiguous heap memory. */
    if (oe_iov_pack(msg->msg_iov, (int)msg->msg_iovlen, &buf, &buf_size) != 0)
        OE_RAISE_ERRNO(OE_ENOMEM);

    /* Call the host. */
    if (oe_posix_sendmsg_ocall(
            &ret,
            sock->host_fd,
            msg->msg_name,
            msg->msg_namelen,
            buf,
            msg->msg_iovlen,
            buf_size,
            msg->msg_control,
            msg->msg_controllen,
            flags) != OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

done:

    if (buf)
        oe_free(buf);

    return ret;
}

static int _hostsock_close(oe_fd_t* sock_)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_close_socket_ocall(&ret, sock->host_fd) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (ret == 0)
        oe_free(sock);

done:

    return ret;
}

static int _hostsock_fcntl(oe_fd_t* sock_, int cmd, uint64_t arg)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_fcntl_ocall(&ret, sock->host_fd, cmd, arg) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:

    return ret;
}

static int _hostsock_dup(oe_fd_t* sock_, oe_fd_t** new_sock_out)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    sock_t* new_sock = NULL;

    oe_errno = 0;

    if (new_sock_out)
        *new_sock_out = NULL;

    if (!sock || !new_sock_out)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(new_sock = _new_sock()))
        OE_RAISE_ERRNO(OE_ENOMEM);

    /* Call the host. */
    {
        oe_host_fd_t retval = -1;

        if (oe_posix_dup_ocall(&retval, sock->host_fd) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);

        if (retval == -1)
            OE_RAISE_ERRNO(oe_errno);

        new_sock->host_fd = retval;
    }

    *new_sock_out = &new_sock->base;
    new_sock = NULL;
    ret = 0;

done:

    if (new_sock)
        oe_free(new_sock);

    return ret;
}

static int _hostsock_getsockopt(
    oe_fd_t* sock_,
    int level,
    int optname,
    void* optval,
    oe_socklen_t* optlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_socklen_t optlen_in = 0;

    oe_errno = 0;

    if (!sock)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (optlen)
        optlen_in = *optlen;

    if (oe_posix_getsockopt_ocall(
            &ret, sock->host_fd, level, optname, optval, optlen_in, optlen) !=
        OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

done:

    return ret;
}

static int _hostsock_setsockopt(
    oe_fd_t* sock_,
    int level,
    int optname,
    const void* optval,
    oe_socklen_t optlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock || !optval || !optlen)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_setsockopt_ocall(
            &ret, sock->host_fd, level, optname, optval, optlen) != OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

done:

    return ret;
}

static int _hostsock_ioctl(oe_fd_t* sock_, unsigned long request, uint64_t arg)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_ioctl_ocall(&ret, sock->host_fd, request, arg) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:

    return ret;
}

static int _hostsock_getpeername(
    oe_fd_t* sock_,
    struct oe_sockaddr* addr,
    oe_socklen_t* addrlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_socklen_t addrlen_in = 0;

    oe_errno = 0;

    if (!sock)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (addrlen)
        addrlen_in = *addrlen;

    if (oe_posix_getpeername_ocall(
            &ret,
            sock->host_fd,
            (struct oe_sockaddr*)addr,
            addrlen_in,
            addrlen) != OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

done:

    return ret;
}

static int _hostsock_getsockname(
    oe_fd_t* sock_,
    struct oe_sockaddr* addr,
    oe_socklen_t* addrlen)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_socklen_t addrlen_in = 0;

    oe_errno = 0;

    if (!sock)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (addrlen)
        addrlen_in = *addrlen;

    if (oe_posix_getsockname_ocall(
            &ret,
            sock->host_fd,
            (struct oe_sockaddr*)addr,
            addrlen_in,
            addrlen) != OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

done:

    return ret;
}

static ssize_t _hostsock_read(oe_fd_t* sock_, void* buf, size_t count)
{
    return _hostsock_recv(sock_, buf, count, 0);
}

static ssize_t _hostsock_write(oe_fd_t* sock_, const void* buf, size_t count)
{
    return _hostsock_send(sock_, buf, count, 0);
}

static ssize_t _hostsock_readv(
    oe_fd_t* desc,
    const struct oe_iovec* iov,
    int iovcnt)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(desc);
    void* buf = NULL;
    size_t buf_size = 0;

    if (!sock || (!iov && iovcnt) || iovcnt < 0 || iovcnt > OE_IOV_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Flatten the IO vector into contiguous heap memory. */
    if (oe_iov_pack(iov, iovcnt, &buf, &buf_size) != 0)
        OE_RAISE_ERRNO(OE_ENOMEM);

    /* Call the host. */
    if (oe_posix_recvv_ocall(&ret, sock->host_fd, buf, iovcnt, buf_size) !=
        OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    /* Synchronize data read with IO vector. */
    if (oe_iov_sync(iov, iovcnt, buf, buf_size) != 0)
        OE_RAISE_ERRNO(OE_EINVAL);

done:

    if (buf)
        oe_free(buf);

    return ret;
}

static ssize_t _hostsock_writev(
    oe_fd_t* desc,
    const struct oe_iovec* iov,
    int iovcnt)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(desc);
    void* buf = NULL;
    size_t buf_size = 0;

    if (!sock || !iov || iovcnt < 0 || iovcnt > OE_IOV_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Flatten the IO vector into contiguous heap memory. */
    if (oe_iov_pack(iov, iovcnt, &buf, &buf_size) != 0)
        OE_RAISE_ERRNO(OE_ENOMEM);

    /* Call the host. */
    if (oe_posix_sendv_ocall(&ret, sock->host_fd, buf, iovcnt, buf_size) !=
        OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

done:

    if (buf)
        oe_free(buf);

    return ret;
}

static int _hostsock_shutdown(oe_fd_t* sock_, int how)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_shutdown_ocall(&ret, sock->host_fd, how) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:

    return ret;
}

/* The release method for the socket interface device. */
static int _hostsock_device_release(oe_device_t* device_)
{
    int ret = -1;
    device_t* device = _cast_device(device_);

    oe_errno = 0;

    if (!device)
        OE_RAISE_ERRNO(OE_EINVAL);

    // This device is registered by oe_load_module_host_socket_interface() and
    // is static, so there are no resources to reclaim here.

    ret = 0;

done:

    return ret;
}

static oe_host_fd_t _hostsock_get_host_fd(oe_fd_t* sock_)
{
    sock_t* sock = _cast_sock(sock_);
    return sock->host_fd;
}

static oe_socket_ops_t _sock_ops = {
    .fd.dup = _hostsock_dup,
    .fd.ioctl = _hostsock_ioctl,
    .fd.fcntl = _hostsock_fcntl,
    .fd.read = _hostsock_read,
    .fd.write = _hostsock_write,
    .fd.readv = _hostsock_readv,
    .fd.writev = _hostsock_writev,
    .fd.get_host_fd = _hostsock_get_host_fd,
    .fd.close = _hostsock_close,
    .accept = _hostsock_accept,
    .bind = _hostsock_bind,
    .listen = _hostsock_listen,
    .shutdown = _hostsock_shutdown,
    .getsockopt = _hostsock_getsockopt,
    .setsockopt = _hostsock_setsockopt,
    .getpeername = _hostsock_getpeername,
    .getsockname = _hostsock_getsockname,
    .recv = _hostsock_recv,
    .send = _hostsock_send,
    .recvfrom = _hostsock_recvfrom,
    .sendto = _hostsock_sendto,
    .recvmsg = _hostsock_recvmsg,
    .sendmsg = _hostsock_sendmsg,
    .connect = _hostsock_connect,
};

static oe_socket_ops_t _get_socket_ops(void)
{
    return _sock_ops;
};

// clang-format off
static device_t _device = {
    .base.type = OE_DEVICE_TYPE_SOCKET_INTERFACE,
    .base.name = OE_DEVICE_NAME_HOST_SOCKET_INTERFACE,
    .base.ops.socket =
    {
        .base.release = _hostsock_device_release,
        .socket = _hostsock_device_socket,
        .socketpair = _hostsock_device_socketpair,
    },
    .magic = DEVICE_MAGIC,
};
// clang-format on

oe_result_t oe_load_module_host_socket_interface(void)
{
    oe_result_t result = OE_UNEXPECTED;
    static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
    static bool _loaded = false;

    oe_spin_lock(&_lock);

    if (!_loaded)
    {
        const uint64_t devid = OE_DEVID_HOST_SOCKET_INTERFACE;

        if (oe_device_table_set(devid, &_device.base) != 0)
        {
            /* Do not propagate errno to caller. */
            oe_errno = 0;
            OE_RAISE(OE_FAILURE);
        }

        _loaded = true;
    }

    result = OE_OK;

done:
    oe_spin_unlock(&_lock);

    return result;
}
