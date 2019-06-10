// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_FCNTL_H
#define _OE_SYSCALL_FCNTL_H

#include <openenclave/bits/defs.h>
#include <openenclave/corelibc/bits/types.h>
#include <openenclave/corelibc/stdarg.h>

struct oe_flock {
    short l_type;
    short l_whence;
    oe_off_t l_start;
    oe_off_t l_len;
    oe_pid_t l_pid;
};

#define oe_flock64 oe_flock

struct oe_f_owner_ex {
    int type;
    oe_pid_t  pid;
};

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
#define OE_F_GETLK64       12
#define OE_F_SETLK64       13
#define OE_F_SETLKW64      14
#define OE_F_SETOWN_EX     15
#define OE_F_GETOWN_EX     16
#define OE_F_GETOWNER_UIDS 17
#define OE_F_OFD_GETLK     36
#define OE_F_OFD_SETLK     37
#define OE_F_OFD_SETLKW    38

// clang-format on

#define OE_AT_FDCWD (-100)
#define OE_AT_REMOVEDIR 0x200

int oe_open(const char* pathname, int flags, oe_mode_t mode);

int oe_open_d(uint64_t devid, const char* pathname, int flags, oe_mode_t mode);

int __oe_fcntl(int fd, int cmd, uint64_t arg);

#if !defined(WIN32) /* __feature_io__ */
OE_INLINE int oe_fcntl(int fd, int cmd, ...)
{
    oe_va_list ap;
    oe_va_start(ap, cmd);
    int r = __oe_fcntl(fd, cmd, oe_va_arg(ap, uint64_t));
    oe_va_end(ap);

    return r;
}
#endif /* !defined(WIN32) */

OE_EXTERNC_END

#endif /* _OE_SYSCALL_FCNTL_H */
