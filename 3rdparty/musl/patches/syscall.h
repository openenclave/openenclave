// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/* This file is a patched version of musl/src/internal/syscall.h.
   The PATCH_COMMAND step of musl_include target replaces the original
   file with this patched version in the build folder.
 */
#ifndef _OE_MUSL_PATCHES_INTERNAL_SYSCALL_H
#define _OE_MUSL_PATCHES_INTERNAL_SYSCALL_H

#include <features.h>
#include <openenclave/internal/syscall/declarations.h>
#include <sys/syscall.h>
#include "syscall_arch.h"

#ifndef SYSCALL_RLIM_INFINITY
#define SYSCALL_RLIM_INFINITY (~0ULL)
#endif

#ifndef SYSCALL_MMAP2_UNIT
#define SYSCALL_MMAP2_UNIT 4096ULL
#endif

#ifndef __SYSCALL_LL_PRW
#define __SYSCALL_LL_PRW(x) __SYSCALL_LL_O(x)
#endif

#ifndef __scc
#define __scc(X) ((long)(X))
typedef long syscall_arg_t;
#endif

hidden long __syscall_ret(unsigned long), __syscall(syscall_arg_t, ...),
    __syscall_cp(
        syscall_arg_t,
        syscall_arg_t,
        syscall_arg_t,
        syscall_arg_t,
        syscall_arg_t,
        syscall_arg_t,
        syscall_arg_t);

#define SYSCALL_ARGS0()
#define SYSCALL_ARGS1(a) __scc(a)
#define SYSCALL_ARGS2(a, b) SYSCALL_ARGS1(a), __scc(b)
#define SYSCALL_ARGS3(a, b, c) SYSCALL_ARGS2(a, b), __scc(c)
#define SYSCALL_ARGS4(a, b, c, d) SYSCALL_ARGS3(a, b, c), __scc(d)
#define SYSCALL_ARGS5(a, b, c, d, e) SYSCALL_ARGS4(a, b, c, d), __scc(e)
#define SYSCALL_ARGS6(a, b, c, d, e, f) SYSCALL_ARGS5(a, b, c, d, e), __scc(f)
#define SYSCALL_ARGS7(a, b, c, d, e, f, g) \
    SYSCALL_ARGS6(a, b, c, d, e, f), __scc(g)

#define SYSCALL_NARGS_X(a, b, c, d, e, f, g, h, n, ...) n
#define SYSCALL_NARGS(...) \
    SYSCALL_NARGS_X(_, ##__VA_ARGS__, 7, 6, 5, 4, 3, 2, 1, 0)
#define SYSCALL_CONCAT_X(a, b) a##b
#define SYSCALL_CONCAT(a, b) SYSCALL_CONCAT_X(a, b)

#define SYSCALL_ARGS(...) \
    SYSCALL_CONCAT(SYSCALL_ARGS, SYSCALL_NARGS(__VA_ARGS__))(__VA_ARGS__)

#define __syscall(index, ...) \
    OE_SYSCALL_NAME(_##index)(SYSCALL_ARGS(__VA_ARGS__))
#define syscall(index, ...) \
    __syscall_ret(OE_SYSCALL_NAME(_##index)(SYSCALL_ARGS(__VA_ARGS__)))

#define socketcall __socketcall
#define socketcall_cp __socketcall_cp

#define SYSCALL_CP_ARGS_X(a, b, c, d, e, f, ...) SYSCALL_ARGS6(a, b, c, d, e, f)
#define SYSCALL_CP_ARGS(...) SYSCALL_CP_ARGS_X(__VA_ARGS__, 0, 0, 0, 0, 0, 0)

#define __syscall_cp(index, ...) \
    OE_SYSCALL_NAME(_##index)(SYSCALL_CP_ARGS(__VA_ARGS__))
#define syscall_cp(index, ...) \
    __syscall_ret(OE_SYSCALL_NAME(_##index)(SYSCALL_CP_ARGS(__VA_ARGS__)))

#ifndef SYSCALL_USE_SOCKETCALL
#define __socketcall(nm, a, b, c, d, e, f) syscall(SYS_##nm, a, b, c, d, e, f)
#define __socketcall_cp(nm, a, b, c, d, e, f) \
    syscall_cp(SYS_##nm, a, b, c, d, e, f)
#else
#define __socketcall(nm, a, b, c, d, e, f) \
    syscall(                               \
        SYS_socketcall,                    \
        __SC_##nm,                         \
        ((long[6]){(long)a, (long)b, (long)c, (long)d, (long)e, (long)f}))
#define __socketcall_cp(nm, a, b, c, d, e, f) \
    syscall_cp(                               \
        SYS_socketcall,                       \
        __SC_##nm,                            \
        ((long[6]){(long)a, (long)b, (long)c, (long)d, (long)e, (long)f}))
#endif

/* fixup legacy 16-bit junk */

#ifdef SYS_getuid32
#undef SYS_lchown
#undef SYS_getuid
#undef SYS_getgid
#undef SYS_geteuid
#undef SYS_getegid
#undef SYS_setreuid
#undef SYS_setregid
#undef SYS_getgroups
#undef SYS_setgroups
#undef SYS_fchown
#undef SYS_setresuid
#undef SYS_getresuid
#undef SYS_setresgid
#undef SYS_getresgid
#undef SYS_chown
#undef SYS_setuid
#undef SYS_setgid
#undef SYS_setfsuid
#undef SYS_setfsgid
#define SYS_lchown SYS_lchown32
#define SYS_getuid SYS_getuid32
#define SYS_getgid SYS_getgid32
#define SYS_geteuid SYS_geteuid32
#define SYS_getegid SYS_getegid32
#define SYS_setreuid SYS_setreuid32
#define SYS_setregid SYS_setregid32
#define SYS_getgroups SYS_getgroups32
#define SYS_setgroups SYS_setgroups32
#define SYS_fchown SYS_fchown32
#define SYS_setresuid SYS_setresuid32
#define SYS_getresuid SYS_getresuid32
#define SYS_setresgid SYS_setresgid32
#define SYS_getresgid SYS_getresgid32
#define SYS_chown SYS_chown32
#define SYS_setuid SYS_setuid32
#define SYS_setgid SYS_setgid32
#define SYS_setfsuid SYS_setfsuid32
#define SYS_setfsgid SYS_setfsgid32
#endif

/* fixup legacy 32-bit-vs-lfs64 junk */

#ifdef SYS_fcntl64
#undef SYS_fcntl
#define SYS_fcntl SYS_fcntl64
#endif

#ifdef SYS_getdents64
#undef SYS_getdents
#define SYS_getdents SYS_getdents64
#endif

#ifdef SYS_ftruncate64
#undef SYS_ftruncate
#undef SYS_truncate
#define SYS_ftruncate SYS_ftruncate64
#define SYS_truncate SYS_truncate64
#endif

#ifdef SYS_stat64
#undef SYS_stat
#define SYS_stat SYS_stat64
#endif

#ifdef SYS_fstat64
#undef SYS_fstat
#define SYS_fstat SYS_fstat64
#endif

#ifdef SYS_lstat64
#undef SYS_lstat
#define SYS_lstat SYS_lstat64
#endif

#ifdef SYS_statfs64
#undef SYS_statfs
#define SYS_statfs SYS_statfs64
#endif

#ifdef SYS_fstatfs64
#undef SYS_fstatfs
#define SYS_fstatfs SYS_fstatfs64
#endif

#if defined(SYS_newfstatat)
#undef SYS_fstatat
#define SYS_fstatat SYS_newfstatat
#elif defined(SYS_fstatat64)
#undef SYS_fstatat
#define SYS_fstatat SYS_fstatat64
#endif

#ifdef SYS_ugetrlimit
#undef SYS_getrlimit
#define SYS_getrlimit SYS_ugetrlimit
#endif

#ifdef SYS__newselect
#undef SYS_select
#define SYS_select SYS__newselect
#endif

#ifdef SYS_pread64
#undef SYS_pread
#undef SYS_pwrite
#define SYS_pread SYS_pread64
#define SYS_pwrite SYS_pwrite64
#endif

#ifdef SYS_fadvise64_64
#undef SYS_fadvise
#define SYS_fadvise SYS_fadvise64_64
#elif defined(SYS_fadvise64)
#undef SYS_fadvise
#define SYS_fadvise SYS_fadvise64
#endif

#ifdef SYS_sendfile64
#undef SYS_sendfile
#define SYS_sendfile SYS_sendfile64
#endif

/* socketcall calls */

#define __SC_socket 1
#define __SC_bind 2
#define __SC_connect 3
#define __SC_listen 4
#define __SC_accept 5
#define __SC_getsockname 6
#define __SC_getpeername 7
#define __SC_socketpair 8
#define __SC_send 9
#define __SC_recv 10
#define __SC_sendto 11
#define __SC_recvfrom 12
#define __SC_shutdown 13
#define __SC_setsockopt 14
#define __SC_getsockopt 15
#define __SC_sendmsg 16
#define __SC_recvmsg 17
#define __SC_accept4 18
#define __SC_recvmmsg 19
#define __SC_sendmmsg 20

#ifdef SYS_open
#define __sys_open(...) __syscall(SYS_open, __VA_ARGS__)
#define sys_open(...) __syscall_ret(__sys_open(__VA_ARGS__))
#define __sys_open_cp(...) __syscall_cp(SYS_open, __VA_ARGS__)
#define sys_open_cp(...) __syscall_ret(__sys_open_cp(__VA_ARGS__))
#else
#define __sys_open(...) __syscall(SYS_openat, __VA_ARGS__)
#define sys_open(...) __syscall_ret(__sys_open(__VA_ARGS__))
#define __sys_open_cp(...) __syscall_cp(SYS_openat, __VA_ARGS__)
#define sys_open_cp(...) __syscall_ret(__sys_open_cp(__VA_ARGS__))
#endif

hidden void __procfdname(char __buf[static 15 + 3 * sizeof(int)], unsigned);

hidden void* __vdsosym(const char*, const char*);

#endif /* _OE_MUSL_PATCHES_INTERNAL_SYSCALL_H */
