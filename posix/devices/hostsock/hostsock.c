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
#include <openenclave/internal/posix/raise.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/bits/safecrt.h>
#include "posix_t.h"

#define SOCKET_MAGIC 0x536f636b
#define DEVICE_NAME "hostsock"

static size_t _get_iov_size(const struct oe_iovec* iov, size_t iov_len)
{
    size_t size = 0;

    for (size_t i = 0; i < iov_len; i++)
        size += iov[i].iov_len;

    return size;
}

static int _deflate_iov(
    const struct oe_iovec* iov,
    size_t iov_len,
    void* buf_,
    size_t buf_len)
{
    int ret = -1;
    uint8_t* buf = (uint8_t*)buf_;

    if (!iov || (buf_len && !buf))
        goto done;

    for (size_t i = 0; i < iov_len; i++)
    {
        const void* base = iov[i].iov_base;
        size_t len = iov[i].iov_len;

        if (len > buf_len)
            goto done;

        if (oe_memcpy_s(buf, buf_len, base, len) != OE_OK)
            goto done;

        buf += len;
        buf_len -= len;
    }

    ret = 0;

done:
    return ret;
}

static int _inflate_iov(
    const void* buf_,
    size_t buf_len,
    struct oe_iovec* iov,
    size_t iov_len)
{
    int ret = -1;
    const uint8_t* buf = (uint8_t*)buf_;

    if (!buf || !iov)
        goto done;

    for (size_t i = 0; i < iov_len && buf_len; i++)
    {
        void* base = iov[i].iov_base;
        size_t len = iov[i].iov_len;
        size_t min = (len < buf_len) ? len : buf_len;

        if (oe_memcpy_s(base, len, buf, min) != OE_OK)
            goto done;

        buf += min;
        buf_len -= min;
    }

    ret = 0;

done:
    return ret;
}

typedef struct _sock
{
    struct _oe_device base;
    uint32_t magic;
    oe_host_fd_t host_fd;
} sock_t;

static oe_sock_ops_t* _get_ops(void);

static sock_t* _new_sock(void)
{
    sock_t* sock = NULL;

    if (!(sock = oe_calloc(1, sizeof(sock_t))))
        return NULL;

    sock->base.type = OE_DEVICE_TYPE_SOCKET;
    sock->base.name = DEVICE_NAME;
    sock->base.ops.sock = _get_ops();
    sock->magic = SOCKET_MAGIC;

    return sock;
}

static sock_t* _cast_sock(const oe_device_t* device)
{
    sock_t* sock = (sock_t*)device;

    if (sock == NULL || sock->magic != SOCKET_MAGIC)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return sock;
}

static sock_t _hostsock;

static ssize_t _hostsock_read(oe_device_t*, void* buf, size_t count);

static int _hostsock_close(oe_device_t*);

static oe_device_t* _hostsock_socket(
    oe_device_t* dev,
    int domain,
    int type,
    int protocol)
{
    oe_device_t* ret = NULL;
    sock_t* sock = _cast_sock(dev);
    sock_t* new_sock = NULL;

    oe_errno = 0;

    if (!sock)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* ATTN: remove OE_AF_HOST */
    if (domain == OE_AF_HOST)
        domain = OE_AF_INET;

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

static ssize_t _hostsock_socketpair(
    oe_device_t* dev,
    int domain,
    int type,
    int protocol,
    oe_device_t* sv[2])
{
    int ret = -1;
    sock_t* sock = _cast_sock(dev);
    sock_t* pair[2] = {NULL, NULL};

    oe_errno = 0;

    if (!sock)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (domain == OE_AF_HOST)
        domain = OE_AF_INET;

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
            OE_RAISE_ERRNO_MSG(oe_errno, "retval=%d\n", retval);

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

static void _fix_address_family(struct oe_sockaddr* addr)
{
    if (addr->sa_family == OE_AF_HOST)
        addr->sa_family = OE_AF_INET;
}

typedef struct
{
    struct oe_sockaddr addr;
    uint8_t extra[1024];
} sockaddr_t;

static int _hostsock_connect(
    oe_device_t* sock_,
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

    _fix_address_family(&buf.addr);

    /* Call host. */
    if (oe_posix_connect_ocall(&ret, sock->host_fd, &buf.addr, addrlen) !=
        OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

done:
    return ret;
}

static oe_device_t* _hostsock_accept(
    oe_device_t* sock_,
    struct oe_sockaddr* addr,
    oe_socklen_t* addrlen)
{
    oe_device_t* ret = NULL;
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

        _fix_address_family(&buf.addr);
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
    oe_device_t* sock_,
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

    _fix_address_family(&buf.addr);

    /* Call the host. */
    if (oe_posix_bind_ocall(&ret, sock->host_fd, &buf.addr, addrlen) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:

    return ret;
}

static int _hostsock_listen(oe_device_t* sock_, int backlog)
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
    oe_device_t* sock_,
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
    oe_device_t* sock_,
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
    oe_device_t* sock_,
    struct oe_msghdr* msg,
    int flags)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_errno = 0;
    void* buf = NULL;
    size_t buf_len;

    /* Check the parameters. */
    if (!sock || !msg || (msg->msg_iovlen && !msg->msg_iov))
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Get the size the total (flat) size of the msg_iov array. */
    buf_len = _get_iov_size(msg->msg_iov, msg->msg_iovlen);

    /* Allocate the read buffer if its length is non-zero. */
    if (buf_len && !(buf = oe_calloc(1, buf_len)))
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
                buf_len,
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

    /* Copy the buffer back onto the original iov array. */
    if (_inflate_iov(buf, (size_t)ret, msg->msg_iov, msg->msg_iovlen) != 0)
        OE_RAISE_ERRNO(OE_EINVAL);

done:

    if (buf)
        oe_free(buf);

    return ret;
}

static ssize_t _hostsock_send(
    oe_device_t* sock_,
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
    oe_device_t* sock_,
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
    oe_device_t* sock_,
    const struct oe_msghdr* msg,
    int flags)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    void* buf = NULL;
    size_t buf_len;

    oe_errno = 0;

    /* Check the parameters. */
    if (!sock || !msg || (msg->msg_iovlen && !msg->msg_iov))
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Get the size the total (flat) size of the msg_iov array. */
    buf_len = _get_iov_size(msg->msg_iov, msg->msg_iovlen);

    /* Allocate the write buffer if its length is non-zero. */
    if (buf_len && !(buf = oe_calloc(1, buf_len)))
        OE_RAISE_ERRNO(OE_ENOMEM);

    /* Flatten the iov array onto the buffer. */
    if (_deflate_iov(msg->msg_iov, msg->msg_iovlen, buf, buf_len) != 0)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Call the host. */
    if (oe_posix_sendmsg_ocall(
            &ret,
            sock->host_fd,
            msg->msg_name,
            msg->msg_namelen,
            buf,
            buf_len,
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

static int _hostsock_close(oe_device_t* sock_)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_close_ocall(&ret, sock->host_fd) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (ret == 0)
        oe_free(sock);

done:

    return ret;
}

static int _hostsock_fcntl(oe_device_t* sock_, int cmd, uint64_t arg)
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

static int _hostsock_dup(oe_device_t* sock_, oe_device_t** new_sock_out)
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
    oe_device_t* sock_,
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
    oe_device_t* sock_,
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

static int _hostsock_ioctl(
    oe_device_t* sock,
    unsigned long request,
    uint64_t arg)
{
    OE_UNUSED(sock);
    OE_UNUSED(request);
    OE_UNUSED(arg);

    OE_RAISE_ERRNO(OE_ENOTSUP);

done:
    return -1;
}

static int _hostsock_getpeername(
    oe_device_t* sock_,
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
    oe_device_t* sock_,
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

static ssize_t _hostsock_read(oe_device_t* sock_, void* buf, size_t count)
{
    return _hostsock_recv(sock_, buf, count, 0);
}

static ssize_t _hostsock_write(
    oe_device_t* sock_,
    const void* buf,
    size_t count)
{
    return _hostsock_send(sock_, buf, count, 0);
}

static int _hostsock_socket_shutdown(oe_device_t* sock_, int how)
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

static int _hostsock_shutdown_device(oe_device_t* sock_)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);

    oe_errno = 0;

    if (!sock)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_posix_shutdown_sockets_device_ocall(&ret, sock->host_fd) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (ret != -1)
        oe_free(sock);

done:

    return ret;
}

static oe_host_fd_t _hostsock_gethostfd(oe_device_t* sock_)
{
    sock_t* sock = _cast_sock(sock_);
    return sock->host_fd;
}

static oe_sock_ops_t _ops = {
    .base.ioctl = _hostsock_ioctl,
    .base.fcntl = _hostsock_fcntl,
    .base.read = _hostsock_read,
    .base.write = _hostsock_write,
    .base.close = _hostsock_close,
    .base.dup = _hostsock_dup,
    .base.get_host_fd = _hostsock_gethostfd,
    .base.shutdown = _hostsock_shutdown_device,
    .socket = _hostsock_socket,
    .socketpair = _hostsock_socketpair,
    .connect = _hostsock_connect,
    .accept = _hostsock_accept,
    .bind = _hostsock_bind,
    .listen = _hostsock_listen,
    .shutdown = _hostsock_socket_shutdown,
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
};

static oe_sock_ops_t* _get_ops(void)
{
    return &_ops;
}

static sock_t _hostsock = {
    .base.type = OE_DEVICE_TYPE_SOCKET,
    .base.name = DEVICE_NAME,
    .base.ops.sock = &_ops,
    .magic = SOCKET_MAGIC,
};

static oe_once_t _once = OE_ONCE_INITIALIZER;
static bool _loaded;

static void _load_once(void)
{
    oe_result_t result = OE_FAILURE;
    const uint64_t devid = OE_DEVID_HOSTSOCK;

    if (oe_set_device(devid, &_hostsock.base) != 0)
        OE_RAISE_ERRNO(oe_errno);

    result = OE_OK;

done:

    if (result == OE_OK)
        _loaded = true;
}

oe_result_t oe_load_module_hostsock(void)
{
    if (oe_once(&_once, _load_once) != OE_OK || !_loaded)
        return OE_FAILURE;

    return OE_OK;
}
