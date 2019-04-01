// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openenclave/internal/hostsock.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../../common/hostsockargs.h"

void oe_handle_hostsock_ocall(void* args_)
{
    oe_hostsock_args_t* args = (oe_hostsock_args_t*)args_;
    socklen_t* addrlen = NULL;
    struct sockaddr* paddr = NULL;

    /* ATTN: handle errno propagation. */

    if (!args)
        return;

    args->err = 0;
    switch (args->op)
    {
        case OE_HOSTSOCK_OP_NONE:
        {
            break;
        }
        case OE_HOSTSOCK_OP_SOCKET:
        {
            args->u.socket.ret = socket(
                args->u.socket.domain,
                args->u.socket.type,
                args->u.socket.protocol);
            break;
        }
        case OE_HOSTSOCK_OP_CLOSE:
        {
            args->u.close.ret = close((int)args->u.close.host_fd);
            break;
        }
        case OE_HOSTSOCK_OP_DUP:
        {
            args->u.dup.ret = dup((int)args->u.dup.host_fd);
            break;
        }
        case OE_HOSTSOCK_OP_RECV:
        {
            args->u.recv.ret = recv(
                (int)args->u.recv.host_fd,
                args->buf,
                args->u.recv.count,
                args->u.recv.flags);
            break;
        }
        case OE_HOSTSOCK_OP_RECVFROM:
        {
            args->u.recvfrom.ret = recvfrom(
                (int)args->u.recvfrom.host_fd,
                args->buf,
                args->u.recvfrom.count,
                args->u.recvfrom.flags,
                (struct sockaddr*)(args->buf + args->u.recvfrom.count),
                &args->u.recvfrom.addrlen);
            break;
        }
        case OE_HOSTSOCK_OP_RECVMSG:
        {
            args->u.recvmsg.ret = recvmsg(
                (int)args->u.recvmsg.host_fd,
                (struct msghdr*)args->buf,
                args->u.recvmsg.flags);
            break;
        }
        case OE_HOSTSOCK_OP_SEND:
        {
            args->u.send.ret = send(
                (int)args->u.send.host_fd,
                args->buf,
                args->u.send.count,
                args->u.send.flags);
            break;
        }
        case OE_HOSTSOCK_OP_SENDTO:
        {
            args->u.sendto.ret = sendto(
                (int)args->u.sendto.host_fd,
                args->buf,
                args->u.sendto.count,
                args->u.sendto.flags,
                (const struct sockaddr*)(args->buf + args->u.sendto.count),
                args->u.sendto.addrlen);
            break;
        }
        case OE_HOSTSOCK_OP_SENDMSG:
        {
            args->u.sendmsg.ret = sendmsg(
                (int)args->u.sendmsg.host_fd,
                (const struct msghdr*)args->buf,
                args->u.sendmsg.flags);
            break;
        }
        case OE_HOSTSOCK_OP_CONNECT:
        {
            args->u.connect.ret = connect(
                (int)args->u.connect.host_fd,
                (const struct sockaddr*)args->buf,
                args->u.connect.addrlen);
            break;
        }
        case OE_HOSTSOCK_OP_ACCEPT:
        {
            if (args->u.accept.addrlen != (socklen_t)-1)
            {
                addrlen = &args->u.accept.addrlen;
                paddr = (struct sockaddr*)args->buf;
            }
            args->u.accept.ret = accept(
                (int)args->u.accept.host_fd, (struct sockaddr*)paddr, addrlen);
            break;
        }
        case OE_HOSTSOCK_OP_BIND:
        {
            args->u.bind.ret = bind(
                (int)args->u.bind.host_fd,
                (const struct sockaddr*)args->buf,
                args->u.bind.addrlen);
            break;
        }
        case OE_HOSTSOCK_OP_LISTEN:
        {
            args->u.listen.ret =
                listen((int)args->u.listen.host_fd, args->u.listen.backlog);
            break;
        }
        case OE_HOSTSOCK_OP_SOCK_SHUTDOWN:
        {
            args->u.sock_shutdown.ret = shutdown(
                (int)args->u.sock_shutdown.host_fd, args->u.sock_shutdown.how);
            break;
        }
        case OE_HOSTSOCK_OP_GETSOCKOPT:
        {
            args->u.getsockopt.ret = getsockopt(
                (int)args->u.getsockopt.host_fd,
                args->u.getsockopt.level,
                args->u.getsockopt.optname,
                args->buf,
                &args->u.getsockopt.optlen);
            break;
        }
        case OE_HOSTSOCK_OP_SETSOCKOPT:
        {
            args->u.setsockopt.ret = getsockopt(
                (int)args->u.setsockopt.host_fd,
                args->u.setsockopt.level,
                args->u.setsockopt.optname,
                args->buf,
                &args->u.setsockopt.optlen);
            break;
        }
        case OE_HOSTSOCK_OP_GETPEERNAME:
        {
            args->u.getpeername.ret = getpeername(
                (int)args->u.getpeername.host_fd,
                (struct sockaddr*)args->buf,
                &args->u.getpeername.addrlen);
            break;
        }
        case OE_HOSTSOCK_OP_GETSOCKNAME:
        {
            args->u.getsockname.ret = getsockname(
                (int)args->u.getsockname.host_fd,
                (struct sockaddr*)args->buf,
                &args->u.getsockname.addrlen);
            break;
        }
        case OE_HOSTSOCK_OP_SHUTDOWN_DEVICE:
        {
            // 2do
            break;
        }
        default:
        {
            // Invalid
            break;
        }
    }
    args->err = errno;
}
