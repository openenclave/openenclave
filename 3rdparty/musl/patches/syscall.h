// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/* This file is a patched version of musl/src/internal/syscall.h.
   The PATCH_COMMAND step of musl_include target replaces the original
   file with this patched version in the build folder.
 */
#ifndef _OE_MUSL_PATCHES_INTERNAL_SYSCALL_H
#define _OE_MUSL_PATCHES_INTERNAL_SYSCALL_H

#include <features.h>

// Include OE's syscall declarations.
#include <openenclave/internal/syscall/declarations.h>

#include <sys/syscall.h>
#include "syscall_arch.h"

#ifndef SYSCALL_RLIM_INFINITY
#define SYSCALL_RLIM_INFINITY (~0ULL)
#endif

#ifndef SYSCALL_MMAP2_UNIT
#define SYSCALL_MMAP2_UNIT 4096ULL
#endif

#ifndef __SYSCALL_LL_O
#define __SYSCALL_LL_O(x) (x)
#endif

// This __SYSCALL_LL_PRW must be defined here to prevent compile errors.
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

// Syscalls can be called with upto 6 parameters.
// Wrap each parameter within a __scc call.
#define SYSCALL_ARGS0()
#define SYSCALL_ARGS1(a) __scc(a)
#define SYSCALL_ARGS2(a, b) SYSCALL_ARGS1(a), __scc(b)
#define SYSCALL_ARGS3(a, b, c) SYSCALL_ARGS2(a, b), __scc(c)
#define SYSCALL_ARGS4(a, b, c, d) SYSCALL_ARGS3(a, b, c), __scc(d)
#define SYSCALL_ARGS5(a, b, c, d, e) SYSCALL_ARGS4(a, b, c, d), __scc(e)
#define SYSCALL_ARGS6(a, b, c, d, e, f) SYSCALL_ARGS5(a, b, c, d, e), __scc(f)

// Determine the number of supplied parameters.
#define SYSCALL_NARGS_X(a, b, c, d, e, f, g, n, ...) n
#define SYSCALL_NARGS(...) \
    SYSCALL_NARGS_X(_, ##__VA_ARGS__, 6, 5, 4, 3, 2, 1, 0)

// Get the name of the correct SYSCALL_ARGS macro.
// E.g If 5 arguments are supplied, return SYSCALL_NARGS5
#define SYSCALL_CONCAT_X(a, b) a##b
#define SYSCALL_CONCAT(a, b) SYSCALL_CONCAT_X(a, b)

// Wrap each parameter within a __scc call.
#define SYSCALL_ARGS(...) \
    SYSCALL_CONCAT(SYSCALL_ARGS, SYSCALL_NARGS(__VA_ARGS__))(__VA_ARGS__)

// MUSL makes call to __syscall as well as syscall.
// Convert each syscall to a call to the corresponding implementation.
// E.g:
//       __syscall(SYS_open, a, b, c)
// is converted to
//       oe_SYS_open_impl(__scc(a), __scc(b), __scc(c))
#define __syscall(index, ...) \
    OE_SYSCALL_NAME(_##index)(SYSCALL_ARGS(__VA_ARGS__))
#define syscall(index, ...) \
    __syscall_ret(OE_SYSCALL_NAME(_##index)(SYSCALL_ARGS(__VA_ARGS__)))

// __syscall_cp and syscall_cp function always pass 6 parameters to the
// underlying syscall implementation. MUSL sometimes calls these macros instead
// of the
// __syscall and syscall.
#define SYSCALL_CP_ARGS_X(a, b, c, d, e, f, ...) SYSCALL_ARGS6(a, b, c, d, e, f)
#define SYSCALL_CP_ARGS(...) SYSCALL_CP_ARGS_X(__VA_ARGS__, 0, 0, 0, 0, 0, 0)

#define __syscall_cp(index, ...) \
    OE_SYSCALL_NAME(_##index)(SYSCALL_CP_ARGS(__VA_ARGS__))
#define syscall_cp(index, ...) \
    __syscall_ret(OE_SYSCALL_NAME(_##index)(SYSCALL_CP_ARGS(__VA_ARGS__)))

// Sockets are dispatched via the following macros.
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

#define socketcall __socketcall
#define socketcall_cp __socketcall_cp

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

#ifndef SO_RCVTIMEO_OLD
#define SO_RCVTIMEO_OLD 20
#endif
#ifndef SO_SNDTIMEO_OLD
#define SO_SNDTIMEO_OLD 21
#endif

#define SO_TIMESTAMP_OLD 29
#define SO_TIMESTAMPNS_OLD 35
#define SO_TIMESTAMPING_OLD 37
#define SCM_TIMESTAMP_OLD SO_TIMESTAMP_OLD
#define SCM_TIMESTAMPNS_OLD SO_TIMESTAMPNS_OLD
#define SCM_TIMESTAMPING_OLD SO_TIMESTAMPING_OLD

#ifndef SIOCGSTAMP_OLD
#define SIOCGSTAMP_OLD 0x8906
#endif
#ifndef SIOCGSTAMPNS_OLD
#define SIOCGSTAMPNS_OLD 0x8907
#endif

// Open syscall is dispatched via the following macros.
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

// The calls must be declared here to prevent compile errors.
hidden void __procfdname(char __buf[static 15 + 3 * sizeof(int)], unsigned);

hidden void* __vdsosym(const char*, const char*);

#endif /* _OE_MUSL_PATCHES_INTERNAL_SYSCALL_H */
