// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_SIGNAL_H
#define _OE_SYSCALL_SIGNAL_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/bits/types.h>
#include <openenclave/internal/defs.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** OE names:
**
**==============================================================================
*/

#define OE_SIG_ERR ((oe_sighandler_t)-1)
#define OE_SIG_DFL ((oe_sighandler_t)0)
#define OE_SIG_IGN ((oe_sighandler_t)1)
#define OE_SIGINT 2
#define OE_SIGILL 4
#define OE_SIGABRT 6
#define OE_SIGFPE 8
#define OE_SIGSEGV 11
#define OE_SIGTERM 15
#define OE_SIGHUP 1
#define OE_SIGQUIT 3
#define OE_SIGTRAP 5
#define OE_SIGKILL 9
#define OE_SIGPIPE 13
#define OE_SIGALRM 14
#define OE_SIGTTIN 21
#define OE_SIGTTOU 22
#define OE_SIGXCPU 24
#define OE_SIGXFSZ 25
#define OE_SIGVTALRM 26
#define OE_SIGPROF 27
#define OE_SIGWINCH 28
#define OE_SIGBUS 7
#define OE_SIGUSR1 10
#define OE_SIGUSR2 12
#define OE_SIGCHLD 17
#define OE_SIGCONT 18
#define OE_SIGSTOP 19
#define OE_SIGTSTP 20
#define OE_SIGURG 23
#define OE_SIGPOLL 29
#define OE_SIGSYS 31
#define OE_SIGIO OE_SIGPOLL
#define OE_SIGIOT OE_SIGABRT
#define OE_SIGCLD OE_SIGCHLD

// Only flag supported. 3 args for the sighandler rather than 1
#define OE_SA_SIGINFO 0x00000004

#define __OE_SIGSET_NWORDS (1024 / (8 * sizeof(unsigned long int)))

#define __OE_NSIG 32

typedef struct
{
    unsigned long int __val[__OE_SIGSET_NWORDS];
} oe_sigset_t;

typedef void (*oe_sighandler_t)(int);

union oe_sigval {
    int sival_int;
    void* sival_ptr;
};

#define __OE_SIGINFO_T oe_siginfo_t
#include <openenclave/internal/syscall/bits/siginfo.h>
#undef __OE_SIGINFO_T

#define __OE_SIGACTION oe_sigaction
#include <openenclave/internal/syscall/bits/sigaction.h>
#undef __OE_SIGACTION

oe_sighandler_t oe_signal(int signum, oe_sighandler_t handler);

int oe_kill(oe_pid_t pid, int sig);

int oe_sigaction(
    int signum,
    const struct oe_sigaction* act,
    struct oe_sigaction* oldact);

/*
**==============================================================================
**
** Standard-C names:
**
**==============================================================================
*/

#if defined(OE_NEED_STDC_NAMES)

#define SIG_ERR ((sighandler_t)-1)
#define SIG_DFL ((sighandler_t)0)
#define SIG_IGN ((sighandler_t)1)
#define SIGINT OE_SIGINT
#define SIGILL OE_SIGILL
#define SIGABRT OE_SIGABRT
#define SIGFPE OE_SIGFPE
#define SIGSEGV OE_SIGSEGV
#define SIGTERM OE_SIGTERM
#define SIGHUP OE_SIGHUP
#define SIGQUIT OE_SIGQUIT
#define SIGTRAP OE_SIGTRAP
#define SIGKILL OE_SIGKILL
#define SIGPIPE OE_SIGPIPE
#define SIGALRM OE_SIGALRM
#define SIGTTIN OE_SIGTTIN
#define SIGTTOU OE_SIGTTOU
#define SIGXCPU OE_SIGXCPU
#define SIGXFSZ OE_SIGXFSZ
#define SIGVTALRM OE_SIGVTALRM
#define SIGPROF OE_SIGPROF
#define SIGWINCH OE_SIGWINCH
#define SIGBUS OE_SIGBUS
#define SIGUSR1 OE_SIGUSR1
#define SIGUSR2 OE_SIGUSR2
#define SIGCHLD OE_SIGCHLD
#define SIGCONT OE_SIGCONT
#define SIGSTOP OE_SIGSTOP
#define SIGTSTP OE_SIGTSTP
#define SIGURG OE_SIGURG
#define SIGPOLL OE_SIGPOLL
#define SIGSYS OE_SIGSYS
#define SIGIO OE_SIGIO
#define SIGIOT OE_SIGIOT
#define SIGCLD OE_SIGCLD

typedef oe_sigset_t sigset_t;
typedef oe_sighandler_t sighandler_t;

union sigval {
    int sival_int;
    void* sival_ptr;
};

#define __OE_SIGINFO_T siginfo_t
#include <openenclave/internal/syscall/bits/siginfo.h>
#undef __OE_SIGINFO_T

#define __OE_SIGACTION sigaction
#include <openenclave/internal/syscall/bits/sigaction.h>
#undef __OE_SIGACTION

#define sa_handler oe_sa_handler
#define sa_sigaction oe_sa_sigaction
#define sa_mask oe_sa_mask
#define sa_flags oe_sa_flags
#define sa_restorer oe_sa_restorer
#define si_signo oe_si_signo
#define si_errno oe_si_errno
#define si_code oe_si_code
#define si_pid oe_si_pid
#define si_uid oe_si_uid
#define si_tid oe_si_tid
#define si_overrun oe_si_overrun
#define si_sigval oe_si_sigval
#define si_sys_private oe_si_sys_private
#define si_pid oe_si_pid
#define si_uid oe_si_uid
#define sigval oe_sigval

OE_INLINE sighandler_t signal(int signum, sighandler_t handler)
{
    return (sighandler_t)oe_signal(signum, (oe_sighandler_t)handler);
}

OE_INLINE int kill(pid_t pid, int sig)
{
    return oe_kill(pid, sig);
}

OE_INLINE int sigaction(
    int signum,
    const struct sigaction* act,
    struct sigaction* oldact)
{
    return oe_sigaction(
        signum, (struct oe_sigaction*)act, (struct oe_sigaction*)oldact);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_SYSCALL_SIGNAL_H */
