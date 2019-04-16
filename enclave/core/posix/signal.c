// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/signal.h>
#include <openenclave/internal/thread.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/trace.h>
#include "oe_t.h"
// clang-format on

// Poll uses much of the infrastructure from epoll.

static void _handle_ignore(int signum);

static struct oe_sigaction _actions[__OE_NSIG] = {{{0}}};
static oe_sighandler_t _default_actions[__OE_NSIG] = {
    _handle_ignore, _handle_ignore, _handle_ignore, _handle_ignore,
    _handle_ignore, _handle_ignore, _handle_ignore, _handle_ignore,
    _handle_ignore, _handle_ignore, _handle_ignore, _handle_ignore,
    _handle_ignore, _handle_ignore, _handle_ignore, _handle_ignore,
    _handle_ignore, _handle_ignore, _handle_ignore, _handle_ignore,
    _handle_ignore, _handle_ignore, _handle_ignore, _handle_ignore,
    _handle_ignore, _handle_ignore, _handle_ignore, _handle_ignore,
    _handle_ignore, _handle_ignore, _handle_ignore, _handle_ignore};

static void _handle_ignore(int signum)
{
    (void)signum;
}

static void _handle_error(int signum)
{
    (void)signum;
}

int oe_kill(pid_t pid, int signum)
{
    int retval = -1;
    oe_errno = 0;
    oe_result_t result = OE_FAILURE;

    if ((result = oe_posix_kill_ocall(&retval, (int)pid, signum, &oe_errno)) !=
        OE_OK)
    {
        OE_TRACE_ERROR(
            "pid=%d signum=%d %s", pid, signum, oe_result_str(result));
        goto done;
    }

    retval = 0;

done:
    return retval;
}

int oe_sigaction(
    int signum,
    const struct oe_sigaction* act,
    struct oe_sigaction* oldact)
{
    int retval = -1;

    if (signum >= __OE_NSIG)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (oldact)
    {
        *oldact = _actions[signum];
    }

    if (act)
    {
        _actions[signum] = *act;
    }

    retval = 0;
done:
    return retval;
}

oe_sighandler_t oe_signal(int signum, oe_sighandler_t handler)
{
    oe_sighandler_t retval = OE_SIG_ERR;

    if (signum >= __OE_NSIG)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    _actions[signum].__oe_sigaction_handler.oe_sa_handler = handler;

done:
    return retval;
}

int oe_posix_signal_notify_ecall(int signum)
{
    int ret = -1;

    if (signum >= __OE_NSIG)
    {
        oe_errno = EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    if (_actions[signum].oe_sa_flags & OE_SA_SIGINFO)
    {
        // Get some siginfo and populate: This only lasts to the end of the call

        oe_siginfo_t info = {0};
        info.oe_si_signo = signum;
        info.oe_si_errno = oe_errno;
        info.oe_si_code = 0;
        info.__oe_si_fields.__oe_si_kill.oe_si_pid = oe_getpid();
        info.__oe_si_fields.__oe_si_kill.oe_si_uid = oe_getuid();

        /* we don't do a ucontext, and only a minimal info */
        (*_actions[signum].__oe_sigaction_handler.oe_sa_sigaction)(
            signum, &info, NULL);
        ret = 0;
    }
    else
    {
        oe_sighandler_t h;
        h = _actions[signum].__oe_sigaction_handler.oe_sa_handler;

        if (h == OE_SIG_DFL)
        {
            (*_default_actions[signum])(signum);
        }
        else if (h == OE_SIG_ERR)
        {
            _handle_error(signum);
        }
        else if (h == OE_SIG_IGN)
        {
            _handle_ignore(signum);
        }
        else
        {
            (*_actions[signum].__oe_sigaction_handler.oe_sa_handler)(signum);
        }

        ret = 0;
    }

done:
    return ret;
}
