// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_DECLARATIONS_H
#define _OE_SYSCALL_DECLARATIONS_H

#include <bits/syscall.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>

// For OE_SYS_ defines.
// They are just used for asserting that they are equal to the corresponding
// SYS_ ones.
#if __x86_64__ || _M_X64
#include <openenclave/internal/syscall/sys/bits/syscall_x86_64.h>
#elif defined(__aarch64__)
#include <openenclave/internal/syscall/sys/bits/syscall_aarch64.h>
#else
#error Unsupported architecture
#endif

OE_EXTERNC_BEGIN

#define OE_SYSCALL_NAME(index) oe##index##_impl

#define OE_SYSCALL_DISPATCH(index, ...) \
    case OE_##index:                    \
        return OE_SYSCALL_NAME(_##index)(__VA_ARGS__)

#define OE_SYSCALL_ARGS0 void
#define OE_SYSCALL_ARGS1 long arg1
#define OE_SYSCALL_ARGS2 OE_SYSCALL_ARGS1, long arg2
#define OE_SYSCALL_ARGS3 OE_SYSCALL_ARGS2, long arg3
#define OE_SYSCALL_ARGS4 OE_SYSCALL_ARGS3, long arg4
#define OE_SYSCALL_ARGS5 OE_SYSCALL_ARGS4, long arg5
#define OE_SYSCALL_ARGS6 OE_SYSCALL_ARGS5, long arg6
#define OE_SYSCALL_ARGS7 OE_SYSCALL_ARGS6, long arg7

#define OE_DECLARE_SYSCALL0(index)         \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS0)
#define OE_DECLARE_SYSCALL1(index)         \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS1)
#define OE_DECLARE_SYSCALL2(index)         \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS2)
#define OE_DECLARE_SYSCALL3(index)         \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS3)
#define OE_DECLARE_SYSCALL4(index)         \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS4)
#define OE_DECLARE_SYSCALL5(index)         \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS5)
#define OE_DECLARE_SYSCALL6(index)         \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS6)
#define OE_DECLARE_SYSCALL7(index)         \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS7)

#define OE_DEFINE_SYSCALL0 OE_DECLARE_SYSCALL0
#define OE_DEFINE_SYSCALL1 OE_DECLARE_SYSCALL1
#define OE_DEFINE_SYSCALL2 OE_DECLARE_SYSCALL2
#define OE_DEFINE_SYSCALL3 OE_DECLARE_SYSCALL3
#define OE_DEFINE_SYSCALL4 OE_DECLARE_SYSCALL4
#define OE_DEFINE_SYSCALL5 OE_DECLARE_SYSCALL5
#define OE_DEFINE_SYSCALL6 OE_DECLARE_SYSCALL6
#define OE_DEFINE_SYSCALL7 OE_DECLARE_SYSCALL7

/** List of syscalls that are supported within enclaves.
 ** In alphabetical order.
 ** Certain syscalls are available only in some platforms.
 **/

OE_DECLARE_SYSCALL3(SYS_accept);
#if __x86_64__ || _M_X64
OE_DECLARE_SYSCALL2(SYS_access);
#endif
OE_DECLARE_SYSCALL3(SYS_bind);
OE_DECLARE_SYSCALL1(SYS_chdir);
OE_DECLARE_SYSCALL1(SYS_close);
OE_DECLARE_SYSCALL3(SYS_connect);
#if __x86_64__ || _M_X64
OE_DECLARE_SYSCALL2(SYS_creat);
#endif
OE_DECLARE_SYSCALL1(SYS_dup);
#if __x86_64__ || _M_X64
OE_DECLARE_SYSCALL2(SYS_dup2);
#endif
OE_DECLARE_SYSCALL3(SYS_dup3);
#if __x86_64__ || _M_X64
OE_DECLARE_SYSCALL1(SYS_epoll_create);
#endif
OE_DECLARE_SYSCALL1(SYS_epoll_create1);
OE_DECLARE_SYSCALL4(SYS_epoll_ctl);
OE_DECLARE_SYSCALL5(SYS_epoll_pwait);
#if __x86_64__ || _M_X64
OE_DECLARE_SYSCALL4(SYS_epoll_wait);
#endif
OE_DECLARE_SYSCALL1(SYS_exit);
OE_DECLARE_SYSCALL0(SYS_exit_group);
OE_DECLARE_SYSCALL4(SYS_faccessat);
OE_DECLARE_SYSCALL3(SYS_fcntl);
OE_DECLARE_SYSCALL1(SYS_fdatasync);
OE_DECLARE_SYSCALL2(SYS_flock);
OE_DECLARE_SYSCALL2(SYS_fstat);
OE_DECLARE_SYSCALL1(SYS_fsync);
OE_DECLARE_SYSCALL2(SYS_getcwd);
OE_DECLARE_SYSCALL3(SYS_getdents64);
OE_DECLARE_SYSCALL0(SYS_getegid);
OE_DECLARE_SYSCALL0(SYS_geteuid);
OE_DECLARE_SYSCALL0(SYS_getgid);
OE_DECLARE_SYSCALL2(SYS_getgroups);
OE_DECLARE_SYSCALL3(SYS_getpeername);
OE_DECLARE_SYSCALL1(SYS_getpgid);
#if __x86_64__ || _M_X64
OE_DECLARE_SYSCALL0(SYS_getpgrp);
#endif
OE_DECLARE_SYSCALL0(SYS_getpid);
OE_DECLARE_SYSCALL0(SYS_getppid);
OE_DECLARE_SYSCALL3(SYS_getsockname);
OE_DECLARE_SYSCALL5(SYS_getsockopt);
OE_DECLARE_SYSCALL0(SYS_getuid);
OE_DECLARE_SYSCALL6(SYS_ioctl);
#if __x86_64__ || _M_X64
OE_DECLARE_SYSCALL2(SYS_link);
#endif
OE_DECLARE_SYSCALL5(SYS_linkat);
OE_DECLARE_SYSCALL2(SYS_listen);
OE_DECLARE_SYSCALL3(SYS_lseek);
#if __x86_64__ || _M_X64
OE_DECLARE_SYSCALL2(SYS_mkdir);
#endif
OE_DECLARE_SYSCALL3(SYS_mkdirat);
OE_DECLARE_SYSCALL5(SYS_mount);
OE_DECLARE_SYSCALL2(SYS_nanosleep);
OE_DECLARE_SYSCALL4(SYS_newfstatat);
#if __x86_64__ || _M_X64
OE_DECLARE_SYSCALL3(SYS_open);
#endif
OE_DECLARE_SYSCALL4(SYS_openat);
#if __x86_64__ || _M_X64
OE_DECLARE_SYSCALL3(SYS_poll);
#endif
OE_DECLARE_SYSCALL4(SYS_ppoll);
OE_DECLARE_SYSCALL4(SYS_pread64);
OE_DECLARE_SYSCALL5(SYS_pselect6);
OE_DECLARE_SYSCALL4(SYS_pwrite64);
OE_DECLARE_SYSCALL3(SYS_read);
OE_DECLARE_SYSCALL3(SYS_readv);
OE_DECLARE_SYSCALL6(SYS_recvfrom);
OE_DECLARE_SYSCALL3(SYS_recvmsg);
#if __x86_64__ || _M_X64
OE_DECLARE_SYSCALL2(SYS_rename);
#endif
OE_DECLARE_SYSCALL5(SYS_renameat);
#if __x86_64__ || _M_X64
OE_DECLARE_SYSCALL1(SYS_rmdir);
#endif
#if __x86_64__ || _M_X64
OE_DECLARE_SYSCALL5(SYS_select);
#endif
OE_DECLARE_SYSCALL6(SYS_sendto);
OE_DECLARE_SYSCALL3(SYS_sendmsg);
OE_DECLARE_SYSCALL5(SYS_setsockopt);
OE_DECLARE_SYSCALL2(SYS_shutdown);
OE_DECLARE_SYSCALL3(SYS_socket);
OE_DECLARE_SYSCALL4(SYS_socketpair);
#if __x86_64__ || _M_X64
OE_DECLARE_SYSCALL2(SYS_stat);
#endif
OE_DECLARE_SYSCALL2(SYS_truncate);
OE_DECLARE_SYSCALL3(SYS_write);
OE_DECLARE_SYSCALL3(SYS_writev);
OE_DECLARE_SYSCALL1(SYS_uname);
#if __x86_64__ || _M_X64
OE_DECLARE_SYSCALL1(SYS_unlink);
#endif
OE_DECLARE_SYSCALL3(SYS_unlinkat);
OE_DECLARE_SYSCALL2(SYS_umount2);

OE_EXTERNC_END

#endif /* _OE_SYSCALL_DECLARATIONS_H */
