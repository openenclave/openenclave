// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_IOV_H
#define _OE_SYSCALL_IOV_H

#include <openenclave/bits/fs.h>
#include <openenclave/bits/result.h>
#include <openenclave/internal/syscall/fd.h>
#include <openenclave/internal/syscall/sys/stat.h>

OE_EXTERNC_BEGIN

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

#endif // _OE_SYSCALL_IOV_H
