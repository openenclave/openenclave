// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_SYS_UIO_H
#define _OE_SYSCALL_SYS_UIO_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

struct oe_iovec
{
    void* iov_base;
    size_t iov_len;
};

ssize_t oe_readv(int fd, const struct oe_iovec* iov, int iovcnt);

ssize_t oe_writev(int fd, const struct oe_iovec* iov, int iovcnt);

OE_EXTERNC_END

#endif /* _OE_SYSCALL_SYS_UIO_H */
