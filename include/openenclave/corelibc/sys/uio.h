// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYS_UIO
#define _OE_SYS_UIO

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

#if defined(OE_NEED_STDC_NAMES)

struct iovec
{
    void* iov_base;
    size_t iov_len;
};

OE_INLINE ssize_t readv(int fd, const struct iovec* iov, int iovcnt)
{
    return oe_readv(fd, (const struct oe_iovec*)iov, iovcnt);
}

OE_INLINE ssize_t writev(int fd, const struct iovec* iov, int iovcnt)
{
    return oe_writev(fd, (const struct oe_iovec*)iov, iovcnt);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_SYS_UIO */
