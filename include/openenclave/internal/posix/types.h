// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_POSIX_TYPES_H
#define _OE_POSIX_TYPES_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef int64_t oe_host_fd_t;

/* Version of struct oe_pollfd with wider descriptor. */
struct oe_host_pollfd
{
    oe_host_fd_t fd;
    short int events;
    short int revents;
};

OE_EXTERNC_END

#endif // _OE_POSIX_TYPES_H
