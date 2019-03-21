// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE

// clang-format off
#include <openenclave/enclave.h>
// clang-format on

#include <openenclave/internal/device.h>
#include <openenclave/internal/sock_ops.h>
#include <openenclave/internal/hostsock.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/hostbatch.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/sys/uio.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/internal/print.h>
#include "../common/hostsockargs.h"

/*
**==============================================================================
**
** host batch:
**
**==============================================================================
*/

static oe_host_batch_t* _host_batch;
static oe_spinlock_t _lock;

static void _atexit_handler()
{
    oe_spin_lock(&_lock);
    oe_host_batch_delete(_host_batch);
    _host_batch = NULL;
    oe_spin_unlock(&_lock);
}

static oe_host_batch_t* _get_host_batch(void)
{
    const size_t BATCH_SIZE = sizeof(oe_hostsock_args_t) + OE_BUFSIZ;

    if (_host_batch == NULL)
    {
        oe_spin_lock(&_lock);

        if (_host_batch == NULL)
        {
            _host_batch = oe_host_batch_new(BATCH_SIZE);
            oe_atexit(_atexit_handler);
        }

        oe_spin_unlock(&_lock);
    }

    return _host_batch;
}

static ssize_t _copy_iov(
    struct oe_msghdr* dst,
    const struct oe_msghdr* src,
    ssize_t bytes_available)

{
    ssize_t required = -1;
    size_t iovidx = 0;
    uint8_t* pbuf = (uint8_t*)dst;

    pbuf += src->msg_namelen;
    pbuf += sizeof(struct oe_iovec) * src->msg_iovlen;
    for (iovidx = 0; iovidx < src->msg_iovlen; iovidx++)
    {
        pbuf += src->msg_iov[iovidx].iov_len;
    }
    pbuf += src->msg_controllen;

    required = (pbuf - (uint8_t*)dst);
    if (!dst)
    {
        return (ssize_t)required;
    }

    if ((ssize_t)required > bytes_available)
    {
        return -1;
    }

    pbuf = (uint8_t*)dst;
    dst->msg_namelen = src->msg_namelen;
    dst->msg_name = pbuf;
    memcpy(dst->msg_name, src->msg_name, src->msg_namelen);
    pbuf += src->msg_namelen;

    dst->msg_iovlen = src->msg_iovlen;
    pbuf += sizeof(struct oe_iovec) * src->msg_iovlen;

    for (iovidx = 0; iovidx < src->msg_iovlen; iovidx++)
    {
        dst->msg_iov[iovidx].iov_base = pbuf;
        dst->msg_iov[iovidx].iov_len = src->msg_iov[iovidx].iov_len;
        memcpy(
            dst->msg_iov[iovidx].iov_base,
            src->msg_iov[iovidx].iov_base,
            src->msg_iov[iovidx].iov_len);
        pbuf += src->msg_iov[iovidx].iov_len;
    }

    dst->msg_controllen = src->msg_controllen;
    dst->msg_control = pbuf;
    memcpy(dst->msg_control, src->msg_control, src->msg_controllen);
    pbuf += dst->msg_controllen;

    dst->msg_flags = src->msg_flags;

    return required;
}

/*
**==============================================================================
**
** hostsock operations:
**
**==============================================================================
*/

#define SOCKET_MAGIC 0x536f636b

typedef oe_hostsock_args_t args_t;

typedef struct _sock
{
    struct _oe_device base;
    uint32_t magic;
    int64_t host_fd;
    uint64_t ready_mask;
    // epoll registers with us.
    int max_event_fds;
    int num_event_fds;
    // oe_event_device_t *event_fds;
} sock_t;

static sock_t* _cast_sock(const oe_device_t* device)
{
    sock_t* sock = (sock_t*)device;

    if (sock == NULL || sock->magic != SOCKET_MAGIC)
        return NULL;

    return sock;
}

static sock_t _hostsock;
static ssize_t _hostsock_read(oe_device_t*, void* buf, size_t count);

static int _hostsock_close(oe_device_t*);

static int _hostsock_clone(oe_device_t* device, oe_device_t** new_device)
{
    int ret = -1;
    sock_t* sock = _cast_sock(device);
    sock_t* new_sock = NULL;

    if (!sock || !new_device)
    {
        oe_errno = EINVAL;
        goto done;
    }

    if (!(new_sock = oe_calloc(1, sizeof(sock_t))))
    {
        oe_errno = ENOMEM;
        goto done;
    }

    memcpy(new_sock, sock, sizeof(sock_t));

    *new_device = &new_sock->base;
    ret = 0;

done:
    return ret;
}

static int _hostsock_release(oe_device_t* device)
{
    int ret = -1;
    sock_t* sock = _cast_sock(device);

    if (!sock)
    {
        oe_errno = EINVAL;
        goto done;
    }

    oe_free(sock);
    ret = 0;

done:
    return ret;
}

static oe_device_t* _hostsock_socket(
    oe_device_t* sock_,
    int domain,
    int type,
    int protocol)
{
    oe_device_t* ret = NULL;
    sock_t* sock = NULL;
    args_t* args = NULL;
    oe_host_batch_t* batch = _get_host_batch();

    oe_errno = 0;

    if (!batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    (void)_hostsock_clone(sock_, &ret);
    sock = _cast_sock(ret);
    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_SOCKET;
        args->u.socket.ret = -1;

        if (domain == OE_AF_HOST)
            domain = OE_AF_INET;

        args->u.socket.domain = domain;
        args->u.socket.type = type;
        args->u.socket.protocol = protocol;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (args->u.socket.ret < 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Output */
    {
        sock->base.type = OE_DEVICETYPE_SOCKET;
        sock->base.size = sizeof(sock_t);
        sock->magic = SOCKET_MAGIC;
        sock->base.ops.socket = _hostsock.base.ops.socket;
        sock->host_fd = args->u.socket.ret;
    }

    sock = NULL;

done:

    if (sock)
        oe_free(sock);

    if (args)
        oe_host_batch_free(batch);

    return ret;
}

static ssize_t _hostsock_socketpair(
    oe_device_t* sock_,
    int domain,
    int type,
    int protocol,
    oe_device_t* retdevs[2])
{
    ssize_t ret = -1;
    oe_device_t* retdev1 = NULL;
    oe_device_t* retdev2 = NULL;
    sock_t* sock1 = NULL;
    sock_t* sock2 = NULL;
    args_t* args = NULL;
    oe_host_batch_t* batch = _get_host_batch();

    oe_errno = 0;

    if (!batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    (void)_hostsock_clone(sock_, &retdev1);
    (void)_hostsock_clone(sock_, &retdev2);
    sock1 = _cast_sock(retdev1);
    sock2 = _cast_sock(retdev2);
    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_SOCKETPAIR;
        args->u.socketpair.ret = -1;

        if (domain == OE_AF_HOST)
            domain = OE_AF_INET;

        args->u.socketpair.domain = domain;
        args->u.socketpair.type = type;
        args->u.socketpair.protocol = protocol;
        args->u.socketpair.hostfd1 = -1;
        args->u.socketpair.hostfd2 = -1;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        ret = args->u.socketpair.ret;
        if (args->u.socketpair.ret < 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Output */
    {
        sock1->base.type = OE_DEVICETYPE_SOCKET;
        sock1->base.size = sizeof(sock_t);
        sock1->magic = SOCKET_MAGIC;
        sock1->base.ops.socket = _hostsock.base.ops.socket;
        sock1->host_fd = args->u.socketpair.hostfd1;

        sock2->base.type = OE_DEVICETYPE_SOCKET;
        sock2->base.size = sizeof(sock_t);
        sock2->magic = SOCKET_MAGIC;
        sock2->base.ops.socket = _hostsock.base.ops.socket;
        sock1->host_fd = args->u.socketpair.hostfd2;
        retdevs[0] = retdev1;
        retdevs[1] = retdev2;
    }

    sock1 = NULL;

done:

    if (sock1)
    {
        oe_free(sock1);
        oe_free(sock2);
    }

    if (args)
        oe_host_batch_free(batch);

    return ret;
}

static void _fix_address_family(struct oe_sockaddr* addr)
{
    if (addr->sa_family == OE_AF_HOST)
        addr->sa_family = OE_AF_INET;
}

static int _hostsock_connect(
    oe_device_t* sock_,
    const struct oe_sockaddr* addr,
    socklen_t addrlen)
{
    int64_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || !addr)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + addrlen)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_CONNECT;
        args->u.connect.ret = -1;
        args->u.connect.host_fd = sock->host_fd;
        args->u.connect.addrlen = addrlen;
        memcpy(args->buf, addr, addrlen);
        _fix_address_family((struct oe_sockaddr*)args->buf);
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.connect.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

done:
    return (int)ret;
}

static int _hostsock_accept(
    oe_device_t* sock_,
    struct oe_sockaddr* addr,
    socklen_t* addrlen)
{
    int64_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || (addr && !addrlen) || (addrlen && !addr))
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        size_t allocsize = sizeof(args_t) + 8;
        if (addrlen)
            allocsize += *addrlen;
        if (!(args = oe_host_batch_calloc(batch, allocsize)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_ACCEPT;
        args->u.accept.ret = -1;
        /* The host_id going in is the listend fd */
        args->u.accept.host_fd = sock->host_fd;

        if (addrlen != NULL)
        {
            args->u.accept.addrlen = *addrlen;
            memcpy(args->buf, addr, *addrlen);
            _fix_address_family((struct oe_sockaddr*)args->buf);
        }
        else
        {
            args->u.accept.addrlen = (socklen_t)-1;
        }
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        sock->host_fd =
            args->u.accept.ret; // The host_id going out is the connect fd

        if ((ret = args->u.accept.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Output */
    if (addrlen)
    {
        *addrlen = args->u.accept.addrlen;
        memcpy(addr, args->buf, *addrlen);
    }

done:
    return (int)ret;
}

static int _hostsock_bind(
    oe_device_t* sock_,
    const struct oe_sockaddr* addr,
    socklen_t addrlen)
{
    int64_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || !addr || !addrlen)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + addrlen)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_BIND;
        args->u.bind.ret = -1;
        args->u.bind.host_fd = sock->host_fd;
        args->u.bind.addrlen = addrlen;
        memcpy(args->buf, addr, addrlen);
        _fix_address_family((struct oe_sockaddr*)args->buf);
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.bind.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

done:

    return (int)ret;
}

static int _hostsock_listen(oe_device_t* sock_, int backlog)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock_ || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_LISTEN;
        args->u.listen.ret = -1;
        args->u.listen.host_fd = sock->host_fd;
        args->u.listen.backlog = backlog;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (args->u.listen.ret != 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    ret = 0;

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
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || (count && !buf))
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + count)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_RECV;
        args->u.recv.ret = -1;
        args->u.recv.host_fd = sock->host_fd;
        args->u.recv.count = count;
        args->u.recv.flags = flags;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.recv.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Output */
    {
        memcpy(buf, args->buf, count);
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
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || !msg)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    ssize_t required = _copy_iov(NULL, msg, 0);
    {
        if (!(args = oe_host_batch_calloc(
                  batch, sizeof(args_t) + (size_t)required)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        // the args->buf has [ msg_hdr | iovs | [*iov_base[0] | .. |
        // [*iov_base[n]] | msg_control ]
        //

        args->op = OE_HOSTSOCK_OP_RECVMSG;
        args->u.recvmsg.ret = -1;
        args->u.recvmsg.host_fd = sock->host_fd;
        args->u.recvmsg.flags = flags;

        (void)_copy_iov((struct oe_msghdr*)args->buf, msg, required);
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.recv.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Output */
    {
        if (_copy_iov(msg, (const struct oe_msghdr*)args->buf, required) < 0)
        {
            oe_errno = EINVAL;
            goto done;
        }
    }

done:
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
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || (count && !buf))
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + count)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_SEND;
        args->u.send.ret = -1;
        args->u.send.host_fd = sock->host_fd;
        args->u.send.count = count;
        args->u.send.flags = flags;
        memcpy(args->buf, buf, count);
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.send.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
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
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || !msg)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        ssize_t required = _copy_iov(NULL, msg, 0);
        if (!(args = oe_host_batch_calloc(
                  batch, sizeof(args_t) + (size_t)required)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_SEND;
        args->u.sendmsg.ret = -1;
        args->u.send.host_fd = sock->host_fd;
        args->u.send.flags = flags;
        (void)_copy_iov((struct oe_msghdr*)args->buf, msg, required);
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.send.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

done:
    return ret;
}

static int _hostsock_close(oe_device_t* sock_)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock_ || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_CLOSE;
        args->u.close.ret = -1;
        args->u.close.host_fd = sock->host_fd;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (args->u.close.ret != 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Release the sock_ object. */
    oe_free(sock);

    ret = 0;

done:
    return ret;
}

static int _hostsock_dup(oe_device_t* sock_, oe_device_t** new_sock)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock_ || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_DUP;
        args->u.dup.ret = -1;
        args->u.dup.host_fd = sock->host_fd;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (args->u.dup.ret >= 0)
        {
            sock_t* s = NULL;
            _hostsock_clone(sock_, (oe_device_t**)&s);
            if (!s)
            {
                oe_errno = EINVAL;
                goto done;
            }
            s->host_fd = args->u.dup.ret;
            *new_sock = (oe_device_t*)s;
        }
        else
        {
            oe_errno = args->err;
            goto done;
        }
    }

    ret = 0;

done:
    return ret;
}

static int _hostsock_getsockopt(
    oe_device_t* sock_,
    int level,
    int optname,
    void* optval,
    socklen_t* optlen)
{
    int64_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || !optval || !optlen)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + *optlen)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_GETSOCKOPT;
        args->u.getsockopt.ret = -1;
        args->u.getsockopt.host_fd = sock->host_fd;
        args->u.getsockopt.level = level;
        args->u.getsockopt.optname = optname;
        args->u.getsockopt.optlen = *optlen;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.getsockopt.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Output */
    {
        *optlen = args->u.getsockopt.optlen;
        memcpy(optval, args->buf, *optlen);
    }

done:
    return (int)ret;
}

static int _hostsock_setsockopt(
    oe_device_t* sock_,
    int level,
    int optname,
    const void* optval,
    socklen_t optlen)
{
    int64_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || !optval || !optlen)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + optlen)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_SETSOCKOPT;
        args->u.setsockopt.ret = -1;
        args->u.setsockopt.host_fd = sock->host_fd;
        args->u.setsockopt.level = level;
        args->u.setsockopt.optname = optname;
        args->u.setsockopt.optlen = optlen;
        memcpy(args->buf, optval, optlen);
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.setsockopt.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

done:
    return (int)ret;
}

static int _hostsock_ioctl(
    oe_device_t* sock_,
    unsigned long request,
    oe_va_list ap)
{
    /* Unsupported */
    oe_errno = ENOTTY;
    (void)sock_;
    (void)request;
    (void)ap;
    return -1;
}

static int _hostsock_getpeername(
    oe_device_t* sock_,
    struct oe_sockaddr* addr,
    socklen_t* addrlen)
{
    int64_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || !addr || !addrlen)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + *addrlen)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_ACCEPT;
        args->u.getpeername.ret = -1;
        args->u.getpeername.host_fd = sock->host_fd;
        args->u.getpeername.addrlen = *addrlen;
        memcpy(args->buf, addr, *addrlen);
        _fix_address_family((struct oe_sockaddr*)args->buf);
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.getpeername.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Output */
    {
        *addrlen = args->u.getpeername.addrlen;
        memcpy(addr, args->buf, *addrlen);
    }

done:
    return (int)ret;
}

static int _hostsock_getsockname(
    oe_device_t* sock_,
    struct oe_sockaddr* addr,
    socklen_t* addrlen)
{
    int64_t ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock || !batch || !addr || !addrlen)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + *addrlen)))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_ACCEPT;
        args->u.getsockname.ret = -1;
        args->u.getsockname.host_fd = sock->host_fd;
        args->u.getsockname.addrlen = *addrlen;
        memcpy(args->buf, addr, *addrlen);
        _fix_address_family((struct oe_sockaddr*)args->buf);
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if ((ret = args->u.getsockname.ret) == -1)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Output */
    {
        *addrlen = args->u.getsockname.addrlen;
        memcpy(addr, args->buf, *addrlen);
    }

done:
    return (int)ret;
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
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock_ || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_SOCK_SHUTDOWN;
        args->u.sock_shutdown.ret = -1;
        args->u.sock_shutdown.host_fd = sock->host_fd;
        args->u.sock_shutdown.how = how;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (args->u.sock_shutdown.ret != 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Release the sock_ object. */
    oe_free(sock);

    ret = 0;

done:
    return ret;
}

static int _hostsock_shutdown_device(oe_device_t* sock_)
{
    int ret = -1;
    sock_t* sock = _cast_sock(sock_);
    oe_host_batch_t* batch = _get_host_batch();
    args_t* args = NULL;

    oe_errno = 0;

    /* Check parameters. */
    if (!sock_ || !batch)
    {
        oe_errno = EINVAL;
        goto done;
    }

    /* Input */
    {
        if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
        {
            oe_errno = ENOMEM;
            goto done;
        }

        args->op = OE_HOSTSOCK_OP_SHUTDOWN_DEVICE;
        args->u.shutdown_device.ret = -1;
        args->u.shutdown_device.host_fd = sock->host_fd;
    }

    /* Call */
    {
        if (oe_ocall(OE_OCALL_HOSTSOCK, (uint64_t)args, NULL) != OE_OK)
        {
            oe_errno = EINVAL;
            goto done;
        }

        if (args->u.shutdown_device.ret != 0)
        {
            oe_errno = args->err;
            goto done;
        }
    }

    /* Release the sock_ object. */
    oe_free(sock);

    ret = 0;

done:
    return ret;
}

static int _hostsock_notify(oe_device_t* sock_, uint64_t notification_mask)
{
    sock_t* sock = _cast_sock(sock_);

    if (sock->ready_mask != notification_mask)
    {
        // We notify any epolls in progress.
    }
    sock->ready_mask = notification_mask;
    return 0;
}

static ssize_t _hostsock_gethostfd(oe_device_t* sock_)
{
    sock_t* sock = _cast_sock(sock_);
    return sock->host_fd;
}

static uint64_t _hostsock_readystate(oe_device_t* sock_)
{
    sock_t* sock = _cast_sock(sock_);
    return sock->ready_mask;
}

static oe_sock_ops_t _ops = {
    .base.clone = _hostsock_clone,
    .base.release = _hostsock_release,
    .base.ioctl = _hostsock_ioctl,
    .base.read = _hostsock_read,
    .base.write = _hostsock_write,
    .base.close = _hostsock_close,
    .base.dup = _hostsock_dup,
    .base.notify = _hostsock_notify,
    .base.get_host_fd = _hostsock_gethostfd,
    .base.ready_state = _hostsock_readystate,
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
    .recvmsg = _hostsock_recvmsg,
    .sendmsg = _hostsock_sendmsg,
};

static sock_t _hostsock = {
    .base.type = OE_DEVICETYPE_SOCKET,
    .base.size = sizeof(sock_t),
    .base.ops.socket = &_ops,
    .magic = SOCKET_MAGIC,
    .ready_mask = 0,
    .max_event_fds = 0,
    .num_event_fds = 0,
    // oe_event_device_t *event_fds;
};

oe_device_t* oe_get_hostsock_device(void)
{
    return &_hostsock.base;
}

int oe_register_hostsock_device(void)
{
    int ret = -1;
    const uint64_t devid = OE_DEVID_HOST_SOCKET;

    /* Allocate the device id. */
    if (oe_allocate_devid(devid) != devid)
        goto done;

    /* Add the hostfs device to the device table. */
    if (oe_set_devid_device(devid, oe_get_hostsock_device()) != 0)
        goto done;

    ret = 0;

done:
    return ret;
}
