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

// clang-format off
#define OE_F_DUPFD          0
#define OE_F_GETFD          1
#define OE_F_SETFD          2
#define OE_F_GETFL          3
#define OE_F_SETFL          4
#define OE_F_GETLK          5
#define OE_F_SETLK          6
#define OE_F_SETLKW         7
#define OE_F_SETOWN         8
#define OE_F_GETOWN         9
#define OE_F_SETSIG        10
#define OE_F_GETSIG        11
#define OE_F_SETOWN_EX     15
#define OE_F_GETOWN_EX     16
#define OE_F_GETOWNER_UIDS 17
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

#define F_DUPFD OE_F_DUPFD
#define F_GETFD OE_F_GETFD
#define F_SETFD OE_F_SETFD
#define F_GETFL OE_F_GETFL
#define F_SETFL OE_F_SETFL
#define F_GETLK OE_F_GETLK
#define F_SETLK OE_F_SETLK
#define F_SETLKW OE_F_SETLKW
#define F_SETOWN OE_F_SETOWN
#define F_GETOWN OE_F_GETOWN
#define F_SETSIG OE_F_SETSIG
#define F_GETSIG OE_F_GETSIG
#define F_SETOWN_EX OE_F_SETOWN_EX
#define F_GETOWN_EX OE_F_GETOWN_EX
#define F_GETOWNER_UIDS OE_F_GETOWNER_UIDS

OE_INLINE int open(const char* pathname, int flags, mode_t mode)
{
    return oe_open(pathname, flags, mode);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_FCNTL_H */
