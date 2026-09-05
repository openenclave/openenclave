// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_SYS_IOCTL_H
#define _OE_SYSCALL_SYS_IOCTL_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/stdarg.h>

OE_EXTERNC_BEGIN

#define OE_TCGETS 0x5401
#define OE_TCSETS 0x5402
#define OE_TCSETSW 0x5403
#define OE_TCSETSF 0x5404
#define OE_TCSBRK 0x5409
#define OE_TCXONC 0x540A
#define OE_TCFLSH 0x540B
#define OE_TIOCEXCL 0x540C
#define OE_TIOCNXCL 0x540D
#define OE_TIOCSCTTY 0x540E
#define OE_TIOCGWINSZ 0x5413

int __oe_ioctl(int fd, unsigned long request, uint64_t arg);

int oe_ioctl(int fd, unsigned long request, ...);

OE_EXTERNC_END

#endif /* _OE_SYSCALL_SYS_IOCTL_H */
