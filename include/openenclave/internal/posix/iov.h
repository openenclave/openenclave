// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_POSIX_IOV_H
#define _OE_POSIX_IOV_H

#include <openenclave/bits/fs.h>
#include <openenclave/bits/result.h>
#include <openenclave/corelibc/sys/epoll.h>
#include <openenclave/corelibc/sys/stat.h>
#include <openenclave/internal/posix/fd.h>

OE_EXTERNC_BEGIN

/* Get the deflated size of the IO vector: return (size_t)-1 on overflow. */
size_t oe_iov_compute_size(const struct oe_iovec* iov, size_t iov_count);

int oe_iov_deflate(
    const struct oe_iovec* iov,
    size_t iov_len,
    void** buf,
    size_t* buf_size);

int oe_iov_inflate(
    const void* buf_,
    size_t buf_size,
    struct oe_iovec* iov,
    size_t iov_len);

int oe_iov_pack(
    const struct oe_iovec* iov,
    int iovcnt,
    void** buf_out,
    size_t* buf_size_out);

int oe_iov_sync(
    const struct oe_iovec* iov,
    int iovcnt,
    const void* buf_,
    size_t buf_size);

OE_EXTERNC_END

#endif // _OE_POSIX_IOV_H
