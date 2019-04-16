// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_FCNTL_H
#define _OE_FCNTL_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

// clang-format off
#define OE_O_RDONLY        000000000
#define OE_O_WRONLY        000000001
#define OE_O_RDWR          000000002
#define OE_O_CREAT         000000100
#define OE_O_EXCL          000000200
#define OE_O_NOCTTY        000000400
#define OE_O_TRUNC         000001000
#define OE_O_APPEND        000002000
#define OE_O_NONBLOCK      000004000
#define OE_O_DSYNC         000010000
#define OE_O_SYNC          004010000
#define OE_O_RSYNC         004010000
#define OE_O_DIRECTORY     000200000
#define OE_O_NOFOLLOW      000400000
#define OE_O_CLOEXEC       002000000
#define OE_O_ASYNC         000020000
#define OE_O_DIRECT        000040000
#define OE_O_LARGEFILE     000000000
#define OE_O_NOATIME       001000000
#define OE_O_PATH          010000000
#define OE_O_TMPFILE       020200000
#define OE_O_NDELAY        O_NONBLOCK
// clang-format on

int oe_open(const char* pathname, int flags, mode_t mode);

int oe_open_d(uint64_t devid, const char* pathname, int flags, mode_t mode);

#if defined(OE_NEED_STDC_NAMES)

#define O_RDONLY OE_O_RDONLY
#define O_WRONLY OE_O_WRONLY
#define O_RDWR OE_O_RDWR
#define O_CREAT OE_O_CREAT
#define O_EXCL OE_O_EXCL
#define O_NOCTTY OE_O_NOCTTY
#define O_TRUNC OE_O_TRUNC
#define O_APPEND OE_O_APPEND
#define O_NONBLOCK OE_O_NONBLOCK
#define O_DSYNC OE_O_DSYNC
#define O_SYNC OE_O_SYNC
#define O_RSYNC OE_O_RSYNC
#define O_DIRECTORY OE_O_DIRECTORY
#define O_NOFOLLOW OE_O_NOFOLLOW
#define O_CLOEXEC OE_O_CLOEXEC
#define O_ASYNC OE_O_ASYNC
#define O_DIRECT OE_O_DIRECT
#define O_LARGEFILE OE_O_LARGEFILE
#define O_NOATIME OE_O_NOATIME
#define O_PATH OE_O_PATH
#define O_TMPFILE OE_O_TMPFILE
#define O_NDELAY OE_O_NDELAY

#define F_GETFL 3
#define F_SETFL 4

OE_INLINE int open(const char* pathname, int flags, mode_t mode)
{
    return oe_open(pathname, flags, mode);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_FCNTL_H */
