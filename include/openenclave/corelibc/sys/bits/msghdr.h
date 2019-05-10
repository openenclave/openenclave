// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

struct __OE_MSGHDR
{
    void* msg_name;
    oe_socklen_t msg_namelen;
    struct __OE_IOVEC* msg_iov;
    size_t msg_iovlen;
    void* msg_control;
    size_t msg_controllen;
    int msg_flags;
};
