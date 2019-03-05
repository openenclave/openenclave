// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOSTSOCKARGS_H
#define _OE_HOSTSOCKARGS_H

#include <openenclave/internal/device.h>

OE_EXTERNC_BEGIN

typedef enum _oe_hostsock_op
{
    OE_HOSTSOCK_OP_NONE,
    OE_HOSTSOCK_OP_SOCKET,
    OE_HOSTSOCK_OP_RECV,
    OE_HOSTSOCK_OP_SEND,
    OE_HOSTSOCK_OP_CLOSE,
    OE_HOSTSOCK_OP_CONNECT,
    OE_HOSTSOCK_OP_ACCEPT,
    OE_HOSTSOCK_OP_BIND,
    OE_HOSTSOCK_OP_LISTEN,
    OE_HOSTSOCK_OP_SOCK_SHUTDOWN, // This is shutdown socket, not the device id
                                  // shutdown
    OE_HOSTSOCK_OP_GETSOCKOPT,
    OE_HOSTSOCK_OP_SETSOCKOPT,
    OE_HOSTSOCK_OP_GETPEERNAME,
    OE_HOSTSOCK_OP_GETSOCKNAME,
    OE_HOSTSOCK_OP_SHUTDOWN_DEVICE
} oe_hostsock_op_t;

typedef struct _oe_hostsock_args
{
    oe_hostsock_op_t op;
    int err;
    union {
        struct
        {
            int64_t ret;
            int domain;
            int type;
            int protocol;
        } socket;
        struct
        {
            int64_t ret;
            int64_t host_fd;
            socklen_t addrlen;
        } connect;
        struct
        {
            int64_t ret;
            int64_t host_fd;
            socklen_t addrlen;
        } accept;
        struct
        {
            int64_t ret;
            int64_t host_fd;
            socklen_t addrlen;
        } bind;
        struct
        {
            int64_t ret;
            int64_t host_fd;
            int backlog;
        } listen;
        struct
        {
            ssize_t ret;
            int64_t host_fd;
            int flags;
            // msg struct goes in buffer
        } recvmsg;
        struct
        {
            ssize_t ret;
            int64_t host_fd;
            int flags;
            // msg struct goes in buffer
        } sendmsg;
        struct
        {
            int64_t ret;
            int64_t host_fd;
            size_t count;
            int flags;
        } recv;
        struct
        {
            int64_t ret;
            int64_t host_fd;
            size_t count;
            int flags;
        } send;
        struct
        {
            int64_t ret;
            int64_t host_fd;
            int how;
        } sock_shutdown;
        struct
        {
            int64_t ret;
            int64_t host_fd;
        } close;
        struct
        {
            int64_t ret;
            int64_t host_fd;
            int level;
            int optname;
            socklen_t optlen;
        } setsockopt;
        struct
        {
            int64_t ret;
            int64_t host_fd;
            int level;
            int optname;
            socklen_t optlen;
        } getsockopt;
        struct
        {
            int64_t ret;
            int64_t host_fd;
            socklen_t addrlen;
        } getsockname;
        struct
        {
            int64_t ret;
            int64_t host_fd;
            socklen_t addrlen;
        } getpeername;
        struct
        {
            int64_t ret;
            int64_t host_fd;
        } shutdown_device;
    } u;
    uint8_t buf[];
} oe_hostsock_args_t;

OE_EXTERNC_END

#endif /* _OE_HOSTFSARGS_H */
