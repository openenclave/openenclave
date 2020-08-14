// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_SYSCALL_DECLS_H
#define _OE_INTERNAL_SYSCALL_DECLS_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

#define _OE_SYSCALL_NAME(pfx, idx) pfx##idx
#define OE_SYSCALL_NAME(idx) _OE_SYSCALL_NAME(oe_syscall_, idx)
#define OE_SYSCALL_PROTOTYPE(idx) \
    long OE_SYSCALL_NAME(idx)(    \
        long n,                   \
        long arg1,                \
        long arg2,                \
        long arg3,                \
        long arg4,                \
        long arg5,                \
        long arg6,                \
        long arg7)

#define OE_DECLARE_SYSCALL(idx) OE_SYSCALL_PROTOTYPE(idx);

#define OE_DEFINE_SYSCALL(idx) OE_SYSCALL_PROTOTYPE(idx)

#define __oescc(x) (long)(x)
#define OE_SYSCALL7(n, a, b, c, d, e, f, g) \
    OE_SYSCALL_NAME(n)                      \
    (n,                                     \
     __oescc(a),                            \
     __oescc(b),                            \
     __oescc(c),                            \
     __oescc(d),                            \
     __oescc(e),                            \
     __oescc(f),                            \
     __oescc(g))
#define OE_SYSCALL6(n, a, b, c, d, e, f) OE_SYSCALL7(n, a, b, c, d, e, f, 0)
#define OE_SYSCALL5(n, a, b, c, d, e) OE_SYSCALL6(n, a, b, c, d, e, 0)
#define OE_SYSCALL4(n, a, b, c, d) OE_SYSCALL5(n, a, b, c, d, 0)
#define OE_SYSCALL3(n, a, b, c) OE_SYSCALL4(n, a, b, c, 0)
#define OE_SYSCALL2(n, a, b) OE_SYSCALL3(n, a, b, 0)
#define OE_SYSCALL1(n, a) OE_SYSCALL2(n, a, 0)
#define OE_SYSCALL0(n) OE_SYSCALL1(n, 0)

#define OE_DECLARE_10_SYSCALLS(k) \
    OE_DECLARE_SYSCALL(k##0)      \
    OE_DECLARE_SYSCALL(k##1)      \
    OE_DECLARE_SYSCALL(k##2)      \
    OE_DECLARE_SYSCALL(k##3)      \
    OE_DECLARE_SYSCALL(k##4)      \
    OE_DECLARE_SYSCALL(k##5)      \
    OE_DECLARE_SYSCALL(k##6)      \
    OE_DECLARE_SYSCALL(k##7)      \
    OE_DECLARE_SYSCALL(k##8)      \
    OE_DECLARE_SYSCALL(k##9)

OE_DECLARE_SYSCALL(0)
OE_DECLARE_SYSCALL(1)
OE_DECLARE_SYSCALL(2)
OE_DECLARE_SYSCALL(3)
OE_DECLARE_SYSCALL(4)
OE_DECLARE_SYSCALL(5)
OE_DECLARE_SYSCALL(6)
OE_DECLARE_SYSCALL(7)
OE_DECLARE_SYSCALL(8)
OE_DECLARE_SYSCALL(9)

OE_DECLARE_10_SYSCALLS(1)
OE_DECLARE_10_SYSCALLS(2)
OE_DECLARE_10_SYSCALLS(3)
OE_DECLARE_10_SYSCALLS(4)
OE_DECLARE_10_SYSCALLS(5)
OE_DECLARE_10_SYSCALLS(6)
OE_DECLARE_10_SYSCALLS(7)
OE_DECLARE_10_SYSCALLS(8)
OE_DECLARE_10_SYSCALLS(9)
OE_DECLARE_10_SYSCALLS(10)
OE_DECLARE_10_SYSCALLS(11)
OE_DECLARE_10_SYSCALLS(12)
OE_DECLARE_10_SYSCALLS(13)
OE_DECLARE_10_SYSCALLS(14)
OE_DECLARE_10_SYSCALLS(15)
OE_DECLARE_10_SYSCALLS(16)
OE_DECLARE_10_SYSCALLS(17)
OE_DECLARE_10_SYSCALLS(18)
OE_DECLARE_10_SYSCALLS(19)
OE_DECLARE_10_SYSCALLS(20)
OE_DECLARE_10_SYSCALLS(21)
OE_DECLARE_10_SYSCALLS(22)
OE_DECLARE_10_SYSCALLS(23)
OE_DECLARE_10_SYSCALLS(24)
OE_DECLARE_10_SYSCALLS(25)
OE_DECLARE_10_SYSCALLS(26)
OE_DECLARE_10_SYSCALLS(27)
OE_DECLARE_10_SYSCALLS(28)
OE_DECLARE_10_SYSCALLS(29)
OE_DECLARE_10_SYSCALLS(30)
OE_DECLARE_10_SYSCALLS(31)
OE_DECLARE_10_SYSCALLS(32)
OE_DECLARE_10_SYSCALLS(33)
OE_DECLARE_10_SYSCALLS(34)
OE_DECLARE_10_SYSCALLS(35)

OE_EXTERNC_END

#endif // _OE_INTERNAL_SYSCALL_DECLS_H
