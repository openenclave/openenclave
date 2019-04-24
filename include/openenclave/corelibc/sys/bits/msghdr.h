// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

struct __OE_STRUCT_MSGHDR
{
    void* msg_name;
    socklen_t msg_namelen;
    struct __OE_STRUCT_IOVEC* msg_iov;
    size_t msg_iovlen;
    void* msg_control;
    size_t msg_controllen;
    int msg_flags;
};
