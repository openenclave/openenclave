// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../exception.h"
#include <assert.h>
#include <dlfcn.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/registers.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>
#include "../asmdefs.h"
#include "../enclave.h"

#if !defined(_NSIG) && defined(_SIG_MAXSIG)
#define _NSIG (_SIG_MAXSIG - 1)
#endif

static struct sigaction g_previous_sigaction[_NSIG];

static void _host_signal_handler(
    int sig_num,
    siginfo_t* sig_info,
    void* sig_data)
{
    ucontext_t* context = (ucontext_t*)sig_data;
    oe_host_exception_context_t host_context = {0};
    host_context.rax = (uint64_t)context->uc_mcontext.gregs[REG_RAX];
    host_context.rbx = (uint64_t)context->uc_mcontext.gregs[REG_RBX];
    host_context.rip = (uint64_t)context->uc_mcontext.gregs[REG_RIP];

    // Call platform neutral handler.
    uint64_t action = oe_host_handle_exception(&host_context);

    if (action == OE_EXCEPTION_CONTINUE_EXECUTION)
    {
        // Exception has been handled.
        return;
    }
    else if (g_previous_sigaction[sig_num].sa_handler == SIG_DFL)
    {
        // If not an enclave exception, and no valid previous signal handler is
        // set, raise it again, and let the default signal handler handle it.
        signal(sig_num, SIG_DFL);
        raise(sig_num);
    }
    else
    {
        // If not an enclave exception, and there is old signal handler, we need
        // to transfer the signal to the old signal handler.
        if (!(g_previous_sigaction[sig_num].sa_flags & SA_NODEFER))
        {
            sigaddset(&g_previous_sigaction[sig_num].sa_mask, sig_num);
        }

        sigset_t current_set;
        pthread_sigmask(
            SIG_SETMASK, &g_previous_sigaction[sig_num].sa_mask, &current_set);

        // Call sa_handler or sa_sigaction based on the flags.
        if (g_previous_sigaction[sig_num].sa_flags & SA_SIGINFO)
        {
            g_previous_sigaction[sig_num].sa_sigaction(
                sig_num, sig_info, sig_data);
        }
        else
        {
            g_previous_sigaction[sig_num].sa_handler(sig_num);
        }

        pthread_sigmask(SIG_SETMASK, &current_set, NULL);

        // If the g_previous_sigaction set SA_RESETHAND, it will break the chain
        // which means g_previous_sigaction->next_old_sigact will not be called.
        // This signal handler is not responsible for that, it just follows what
        // the OS does on SA_RESETHAND.
        if (g_previous_sigaction[sig_num].sa_flags & (int)SA_RESETHAND)
            g_previous_sigaction[sig_num].sa_handler = SIG_DFL;
    }

    return;
}

static void _register_signal_handlers(void)
{
    struct sigaction sig_action;

    // Set the signal handler.
    memset(&sig_action, 0, sizeof(sig_action));
    sig_action.sa_sigaction = _host_signal_handler;

    // Use sa_sigaction instead of sa_handler, allow catching the same signal as
    // the one you're currently handling, and automatically restart the system
    // call that interrupted the signal.
    sig_action.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESTART;

    // Should honor the current signal masks.
    sigemptyset(&sig_action.sa_mask);
    if (sigprocmask(SIG_SETMASK, NULL, &sig_action.sa_mask) != 0)
    {
        abort();
    }

    // Unmask the signals we want to receive.
    sigdelset(&sig_action.sa_mask, SIGSEGV);
    sigdelset(&sig_action.sa_mask, SIGFPE);
    sigdelset(&sig_action.sa_mask, SIGILL);
    sigdelset(&sig_action.sa_mask, SIGBUS);
    sigdelset(&sig_action.sa_mask, SIGTRAP);

    // Set the signal handlers, and store the previous signal action into a
    // global array.
    if (sigaction(SIGSEGV, &sig_action, &g_previous_sigaction[SIGSEGV]) != 0)
    {
        abort();
    }

    if (sigaction(SIGFPE, &sig_action, &g_previous_sigaction[SIGFPE]) != 0)
    {
        abort();
    }

    if (sigaction(SIGILL, &sig_action, &g_previous_sigaction[SIGILL]) != 0)
    {
        abort();
    }

    if (sigaction(SIGBUS, &sig_action, &g_previous_sigaction[SIGBUS]) != 0)
    {
        abort();
    }

    if (sigaction(SIGTRAP, &sig_action, &g_previous_sigaction[SIGTRAP]) != 0)
    {
        abort();
    }

    return;
}

// The exception only need to be initialized once per process.
void oe_initialize_host_exception()
{
    _register_signal_handlers();
}
