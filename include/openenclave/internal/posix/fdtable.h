// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_POSIX_FDTABLE_H
#define _OE_POSIX_FDTABLE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/posix/fd.h>

OE_EXTERNC_BEGIN

int oe_fdtable_reassign(int fd, oe_fd_t* desc);

oe_fd_t* oe_fdtable_get(int fd, oe_fd_type_t type);

int oe_fdtable_release(int fd);

int oe_fdtable_assign(oe_fd_t* desc);

OE_EXTERNC_END

#endif // _OE_POSIX_FDTABLE_H
