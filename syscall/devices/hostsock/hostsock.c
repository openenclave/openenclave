// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define _GNU_SOURCE

// clang-format off
#include <openenclave/enclave.h>
// clang-format on

#include <openenclave/internal/syscall/device.h>
#include <openenclave/internal/thread.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/syscall/sys/socket.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/internal/syscall/raise.h>
#include <openenclave/internal/syscall/iov.h>
#include <openenclave/internal/syscall/fd.h>
#include <openenclave/internal/syscall/iov.h>
#include <openenclave/internal/syscall/fcntl.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include "syscall_t.h"

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

        if (oe_syscall_socket_ocall(&retval, domain, type, protocol) != OE_OK)
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

        if (oe_syscall_socketpair_ocall(
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
    if (oe_syscall_connect_ocall(&ret, sock->host_fd, &buf.addr, addrlen) !=
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

        if (oe_syscall_accept_ocall(
                &retval,
                sock->host_fd,
                addr ? &buf.addr : NULL,
                addrlen_in,
                addrlen) != OE_OK)
        {
            OE_RAISE_ERRNO(oe_errno);
        }

        if (retval == -1)
            OE_RAISE_ERRNO_MSG(oe_errno, "retval=%d", retval);

        new_sock->host_fd = retval;

        // copy peer addr to out buffer
        if (addrlen)
        {
            oe_assert(addr);
            if (oe_memcpy_s(addr, addrlen_in, &buf.addr, *addrlen) != OE_OK)
                OE_RAISE_ERRNO(OE_EINVAL);
        }
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
    if (oe_syscall_bind_ocall(&ret, sock->host_fd, &buf.addr, addrlen) != OE_OK)
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

    if (oe_syscall_listen_ocall(&ret, sock->host_fd, backlog) != OE_OK)
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

    /*
     * According to the POSIX specification, when the count is greater
     * than SSIZE_MAX, the result is implementation-defined. OE raises an
     * error in this case.
     * Refer to
     * https://pubs.opengroup.org/onlinepubs/9699919799/functions/recv.html
     * for more detail.
     */
    if (!sock || (count && !buf) || count > OE_SSIZE_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (buf)
    {
        if (oe_memset_s(buf, count, 0, count) != OE_OK)
            OE_RAISE_ERRNO(OE_EINVAL);
    }

    if (oe_syscall_recv_ocall(&ret, sock->host_fd, buf, count, flags) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    /*
     * Guard the special case that a host sets an arbitrarily large value.
     * The return value should not exceed count.
     */
    if (ret > (ssize_t)count)
    {
        ret = -1;
        OE_RAISE_ERRNO(OE_EINVAL);
    }

done:
    return ret;
}

static ssize_t _hostsock_recvfrom(
    oe_fd_t* sock_,
    void* buf,
    size_t count,
    int flags,
    struct oe_sockaddr* src_addr,
    oe_socklen_t* addrlen)
{
    ssize_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_socklen_t addrlen_in = 0;
    oe_socklen_t addrlen_out = 0;

    oe_errno = 0;

    /*
     * According to the POSIX specification, when the count is greater
     * than SSIZE_MAX, the result is implementation-defined. OE raises an
     * error in this case.
     * Refer to
     * https://pubs.opengroup.org/onlinepubs/9699919799/functions/recvfrom.html
     * for more detail.
     */
    if (!sock || (count && !buf) || count > OE_SSIZE_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    /*
     * Update the addrlen_in to the value pointed by addrlen
     * only if both src_addr and addrlen are not NULL.
     */
    if (src_addr && addrlen)
        addrlen_in = *addrlen;

    if (oe_syscall_recvfrom_ocall(
            &ret,
            sock->host_fd,
            buf,
            count,
            flags,
            src_addr,
            addrlen_in,
            &addrlen_out) != OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    /*
     * Update the value pointed by addrlen based on the host-set
     * addrlen_out only if both src_addr and addrlen are not NULL.
     */
    if (src_addr && addrlen)
    {
        /*
         * Error out the case if the addrlen_out is greater than the size
         * of sockaddr_storage.
         */
        if (addrlen_out > sizeof(struct oe_sockaddr_storage))
            OE_RAISE_ERRNO(OE_EINVAL);

        /*
         * Note that the returned value can still exceed the supplied one,
         * which indicates a truncation.
         */
        *addrlen = addrlen_out;
    }

    /*
     * Guard the special case that a host sets an arbitrarily large value.
     * The return value should not exceed count.
     */
    if (ret > (ssize_t)count)
    {
        ret = -1;
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
    size_t data_size = 0;
    oe_socklen_t namelen_out = 0;
    size_t controllen_out = 0;

    /* Check the parameters. */
    if (!sock || !msg || (msg->msg_iovlen && !msg->msg_iov))
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Flatten the IO vector into contiguous heap memory. */
    if (oe_iov_pack(
            msg->msg_iov, (int)msg->msg_iovlen, &buf, &buf_size, &data_size) !=
        0)
        OE_RAISE_ERRNO(OE_ENOMEM);

    /*
     * According to the POSIX specification, when the data_size is greater
     * than SSIZE_MAX, the result is implementation-defined. OE raises an
     * error in this case.
     * Refer to
     * https://pubs.opengroup.org/onlinepubs/9699919799/functions/recvmsg.html
     * for more detail.
     */
    if (data_size > OE_SSIZE_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Call the host. */
    {
        if (oe_syscall_recvmsg_ocall(
                &ret,
                sock->host_fd,
                msg->msg_name,
                msg->msg_namelen,
                &namelen_out,
                buf,
                msg->msg_iovlen,
                buf_size,
                msg->msg_control,
                msg->msg_controllen,
                &controllen_out,
                flags) != OE_OK)
        {
            OE_RAISE_ERRNO(OE_EINVAL);
        }

        if (ret == -1)
            OE_RAISE_ERRNO(oe_errno);
    }

    if (!msg->msg_name)
        msg->msg_namelen = 0;
    else
    {
        /*
         * Error out the case if the namelen_out is greater than the size
         * of sockaddr_storage.
         */
        if (namelen_out > sizeof(struct oe_sockaddr_storage))
            OE_RAISE_ERRNO(OE_EINVAL);

        /*
         * Note that the returned value can still exceed the supplied one,
         * which indicates a truncation.
         */
        if (msg->msg_namelen >= namelen_out)
            msg->msg_namelen = namelen_out;
    }

    if (!msg->msg_control)
        msg->msg_controllen = 0;
    else
    {
        /*
         * Update the msg_controllen only if the supplied value is greater than
         * or equal to the returned value. Otherwise, keep the msg_controllen
         * unchanged, which indicates a truncation. In addition, explicitly
         * setting the MSG_CTRUNC flag when the truncation occurs.
         */
        if (msg->msg_controllen >= controllen_out)
            msg->msg_controllen = controllen_out;
        else
            msg->msg_flags |= OE_MSG_CTRUNC;
    }

    /*
     * Guard the special case that a host sets an arbitrarily large value.
     * The return value should not exceed data_size.
     */
    if (ret > (ssize_t)data_size)
    {
        ret = -1;
        OE_RAISE_ERRNO(OE_EINVAL);
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

    /*
     * According to the POSIX specification, when the count is greater
     * than SSIZE_MAX, the result is implementation-defined. OE raises an
     * error in this case.
     * Refer to
     * https://pubs.opengroup.org/onlinepubs/9699919799/functions/send.html for
     * for more detail.
     */
    if (!sock || (count && !buf) || count > OE_SSIZE_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_syscall_send_ocall(&ret, sock->host_fd, buf, count, flags) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    /*
     * Guard the special case that a host sets an arbitrarily large value.
     * The return value should not exceed count.
     */
    if (ret > (ssize_t)count)
    {
        ret = -1;
        OE_RAISE_ERRNO(OE_EINVAL);
    }

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

    /*
     * According to the POSIX specification, when the count is greater
     * than SSIZE_MAX, the result is implementation-defined. OE raises an
     * error in this case.
     * Refer to
     * https://pubs.opengroup.org/onlinepubs/9699919799/functions/sendto.html
     * for more detail.
     */
    if (!sock || (count && !buf) || count > OE_SSIZE_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_syscall_sendto_ocall(
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

    /*
     * Guard the special case that a host sets an arbitrarily large value.
     * The return value should not exceed count.
     */
    if (ret > (ssize_t)count)
    {
        ret = -1;
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
    size_t data_size = 0;

    oe_errno = 0;

    /* Check the parameters. */
    if (!sock || !msg || (msg->msg_iovlen && !msg->msg_iov))
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Flatten the IO vector into contiguous heap memory. */
    if (oe_iov_pack(
            msg->msg_iov, (int)msg->msg_iovlen, &buf, &buf_size, &data_size) !=
        0)
        OE_RAISE_ERRNO(OE_ENOMEM);

    /*
     * According to the POSIX specification, when the data_size is greater
     * than SSIZE_MAX, the result is implementation-defined. OE raises an
     * error in this case.
     * Refer to
     * https://pubs.opengroup.org/onlinepubs/9699919799/functions/sendmsg.html
     * for more detail.
     */
    if (data_size > OE_SSIZE_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Call the host. */
    if (oe_syscall_sendmsg_ocall(
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

    /*
     * Guard the special case that a host sets an arbitrarily large value.
     * The return value should not exceed data_size.
     */
    if (ret > (ssize_t)data_size)
    {
        ret = -1;
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

    if (oe_syscall_close_socket_ocall(&ret, sock->host_fd) != OE_OK)
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
    void* argout = NULL;
    uint64_t argsize = 0;

    oe_errno = 0;

    if (!sock)
        OE_RAISE_ERRNO(OE_EINVAL);

    switch (cmd)
    {
        case OE_F_GETFD:
        case OE_F_SETFD:
        case OE_F_GETFL:
        case OE_F_SETFL:
            break;

        default:
        case OE_F_DUPFD:
        case OE_F_GETLK64:
        case OE_F_OFD_GETLK:
        case OE_F_SETLK64:
        case OE_F_SETLKW64:
        case OE_F_OFD_SETLK:
        case OE_F_OFD_SETLKW:
            OE_RAISE_ERRNO(OE_EINVAL);
            break;

        // for sockets
        case OE_F_GETSIG: // Returns in return value
        case OE_F_SETSIG: // arg is data value
            break;

        case OE_F_GETOWN: // Returns in return value
        case OE_F_SETOWN: // arg is data value
            break;

        case OE_F_SETOWN_EX:
        case OE_F_GETOWN_EX:
            argsize = sizeof(struct oe_f_owner_ex);
            argout = (void*)arg;
            break;

        case OE_F_GETOWNER_UIDS:
            argsize = sizeof(oe_uid_t[2]);
            argout = (void*)arg;
            break;
    }

    if (oe_syscall_fcntl_ocall(
            &ret, sock->host_fd, cmd, arg, argsize, argout) != OE_OK)
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

        if (oe_syscall_dup_ocall(&retval, sock->host_fd) != OE_OK)
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
    oe_socklen_t optlen_out = 0;

    oe_errno = 0;

    if (!sock || !optval || !optlen)
        OE_RAISE_ERRNO(OE_EINVAL);

    optlen_in = *optlen;

    if (oe_syscall_getsockopt_ocall(
            &ret,
            sock->host_fd,
            level,
            optname,
            optval,
            optlen_in,
            &optlen_out) != OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    /*
     * The POSIX specification for getsockopt states that if the size of optval
     * is greater than the input optlen, then the value stored in the object
     * pointed to by the optval argument shall be silently truncated. We do this
     * in the enclave to ensure that the untrusted host has not returned an
     * arbitrarily large optlen value.
     * Refer to
     * https://pubs.opengroup.org/onlinepubs/9699919799/functions/getsockopt.html
     * for more detail.
     */
    if (optlen_out > optlen_in)
        optlen_out = optlen_in;

    *optlen = optlen_out;

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

    if (oe_syscall_setsockopt_ocall(
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

    /*
     * MUSL uses the TIOCGWINSZ ioctl request to determine whether the file
     * descriptor refers to a terminal device. This request cannot be handled
     * by Windows hosts, so the error is handled on the enclave side. This is
     * the correct behavior since sockets are not terminal devices.
     */
    switch (request)
    {
        default:
            OE_RAISE_ERRNO(OE_ENOTTY);
    }

    if (oe_syscall_ioctl_ocall(&ret, sock->host_fd, request, arg, 0, NULL) !=
        OE_OK)
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
    oe_socklen_t addrlen_out = 0;

    oe_errno = 0;

    if (!sock || !addr || !addrlen)
        OE_RAISE_ERRNO(OE_EINVAL);

    addrlen_in = *addrlen;
    if (addrlen_in < 0)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_syscall_getpeername_ocall(
            &ret,
            sock->host_fd,
            (struct oe_sockaddr*)addr,
            addrlen_in,
            &addrlen_out) != OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    /*
     * Error out the case if the addrlen_out is greater than the size
     * of sockaddr_storage.
     */
    if (addrlen_out > sizeof(struct oe_sockaddr_storage))
        OE_RAISE_ERRNO(OE_EINVAL);

    /*
     * Note that the returned value can still exceed the supplied one,
     * which indicates a truncation. Refer to
     * https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpeername.html
     * for more detail.
     */
    *addrlen = addrlen_out;

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
    oe_socklen_t addrlen_out = 0;

    oe_errno = 0;

    if (!sock || !addr || !addrlen)
        OE_RAISE_ERRNO(OE_EINVAL);

    addrlen_in = *addrlen;
    if (addrlen_in < 0)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_syscall_getsockname_ocall(
            &ret, sock->host_fd, addr, addrlen_in, &addrlen_out) != OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    /*
     * Error out the case if the addrlen_out is greater than the size
     * of sockaddr_storage.
     */
    if (addrlen_out > sizeof(struct oe_sockaddr_storage))
        OE_RAISE_ERRNO(OE_EINVAL);

    /*
     * Note that the returned value can still exceed the supplied one, which
     * indicates a truncation. Refer to
     * https://pubs.opengroup.org/onlinepubs/9699919799/functions/getsockname.html
     * for more detail.
     */
    if (addrlen_in >= addrlen_out)
        *addrlen = addrlen_out;

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
    size_t data_size = 0;

    if (!sock || (!iov && iovcnt) || iovcnt < 0 || iovcnt > OE_IOV_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Flatten the IO vector into contiguous heap memory. */
    if (oe_iov_pack(iov, iovcnt, &buf, &buf_size, &data_size) != 0)
        OE_RAISE_ERRNO(OE_ENOMEM);

    /*
     * According to the POSIX specification, when the data_size is greater
     * than SSIZE_MAX, the result is implementation-defined. OE raises an
     * error in this case.
     * Refer to
     * https://pubs.opengroup.org/onlinepubs/9699919799/functions/readv.html
     * for more detail.
     */
    if (data_size > OE_SSIZE_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Call the host. */
    if (oe_syscall_recvv_ocall(&ret, sock->host_fd, buf, iovcnt, buf_size) !=
        OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    /*
     * Guard the special case that a host sets an arbitrarily large value.
     * The returned value should not exceed data_size.
     */
    if (ret > (ssize_t)(data_size))
    {
        ret = -1;
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    /* Synchronize data read with IO vector. */
    if (ret > 0)
    {
        if (oe_iov_sync(iov, iovcnt, buf, buf_size) != 0)
            OE_RAISE_ERRNO(OE_EINVAL);
    }

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
    size_t data_size = 0;

    if (!sock || !iov || iovcnt < 0 || iovcnt > OE_IOV_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Flatten the IO vector into contiguous heap memory. */
    if (oe_iov_pack(iov, iovcnt, &buf, &buf_size, &data_size) != 0)
        OE_RAISE_ERRNO(OE_ENOMEM);

    /*
     * According to the POSIX specification, when the data_size is greater
     * than SSIZE_MAX, the result is implementation-defined. OE raises an
     * error in this case.
     * Refer to
     * https://pubs.opengroup.org/onlinepubs/9699919799/functions/writev.html
     * for more detail.
     */
    if (data_size > OE_SSIZE_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Call the host. */
    if (oe_syscall_sendv_ocall(&ret, sock->host_fd, buf, iovcnt, buf_size) !=
        OE_OK)
    {
        OE_RAISE_ERRNO(OE_EINVAL);
    }

    /*
     * Guard the special case that a host sets an arbitrarily large value.
     * The return value should not exceed data_size.
     */
    if (ret > (ssize_t)data_size)
    {
        ret = -1;
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

    if (oe_syscall_shutdown_ocall(&ret, sock->host_fd, how) != OE_OK)
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
