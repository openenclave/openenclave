// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <dlfcn.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/registers.h>
#include <openenclave/internal/sgxtypes.h>
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

static void _host_signal_handler(int sigNum, siginfo_t* sigInfo, void* sigData)
{
    ucontext_t* context = (ucontext_t*)sigData;
    uint64_t exitCode = context->uc_mcontext.gregs[REG_RAX];
    uint64_t tcsAddress = context->uc_mcontext.gregs[REG_RBX];
    uint64_t exitAddress = context->uc_mcontext.gregs[REG_RIP];

    // Check if the signal happens inside the enclave.
    if ((exitAddress == (uint64_t)OE_AEP) && (exitCode == ENCLU_ERESUME))
    {
        // Check if the enclave exception happens inside the first pass
        // exception handler.
        ThreadBinding* thread_data = GetThreadBinding();
        if (thread_data->flags & _OE_THREAD_HANDLING_EXCEPTION)
        {
            abort();
        }

        // Call-in enclave to handle the exception.
        oe_enclave_t* enclave = _oe_query_enclave_instance((void*)tcsAddress);
        if (enclave == NULL)
        {
            abort();
        }

        // Set the flag marks this thread is handling an enclave exception.
        thread_data->flags |= _OE_THREAD_HANDLING_EXCEPTION;

        // Call into enclave first pass exception handler.
        uint64_t argOut = 0;
        oe_result_t result =
            oe_ecall(enclave, OE_FUNC_VIRTUAL_EXCEPTION_HANDLER, 0, &argOut);

        // Reset the flag
        thread_data->flags &= (~_OE_THREAD_HANDLING_EXCEPTION);
        if (result == OE_OK && argOut == OE_EXCEPTION_CONTINUE_EXECUTION)
        {
            // This exception has been handled by the enclave. Let's resume.
            return;
        }
        else
        {
            // Un-handled enclave exception happened.
            abort();
        }
    }
    else if (g_previous_sigaction[sigNum].sa_handler == SIG_DFL)
    {
        // If not an enclave exception, and no valid previous signal handler is
        // set, raise it again, and let the default signal handler handle it.
        signal(sigNum, SIG_DFL);
        raise(sigNum);
    }
    else
    {
        // If not an enclave exception, and there is old signal handler, we need
        // to transfer the signal to the old signal handler.
        if (!(g_previous_sigaction[sigNum].sa_flags & SA_NODEFER))
        {
            sigaddset(&g_previous_sigaction[sigNum].sa_mask, sigNum);
        }

        sigset_t currentSet;
        pthread_sigmask(
            SIG_SETMASK, &g_previous_sigaction[sigNum].sa_mask, &currentSet);

        // Call sa_handler or sa_sigaction based on the flags.
        if (g_previous_sigaction[sigNum].sa_flags & SA_SIGINFO)
        {
            g_previous_sigaction[sigNum].sa_sigaction(sigNum, sigInfo, sigData);
        }
        else
        {
            g_previous_sigaction[sigNum].sa_handler(sigNum);
        }

        pthread_sigmask(SIG_SETMASK, &currentSet, NULL);

        // If the g_previous_sigaction set SA_RESETHAND, it will break the chain
        // which means g_previous_sigaction->next_old_sigact will not be called.
        // This signal handler is not responsible for that, it just follows what
        // the OS does on SA_RESETHAND.
        if (g_previous_sigaction[sigNum].sa_flags & SA_RESETHAND)
            g_previous_sigaction[sigNum].sa_handler = SIG_DFL;
    }

    return;
}

static void _register_signal_handlers(void)
{
    struct sigaction sigAction;

    // Set the signal handler.
    memset(&sigAction, 0, sizeof(sigAction));
    sigAction.sa_sigaction = _host_signal_handler;

    // Use sa_sigaction instead of sa_handler, allow catching the same signal as
    // the one you're currently handling, and automatically restart the system
    // call that interrupted the signal.
    sigAction.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESTART;

    // Should honor the current signal masks.
    sigemptyset(&sigAction.sa_mask);
    if (sigprocmask(SIG_SETMASK, NULL, &sigAction.sa_mask) != 0)
    {
        abort();
    }

    // Unmask the signals we want to receive.
    sigdelset(&sigAction.sa_mask, SIGSEGV);
    sigdelset(&sigAction.sa_mask, SIGFPE);
    sigdelset(&sigAction.sa_mask, SIGILL);
    sigdelset(&sigAction.sa_mask, SIGBUS);
    sigdelset(&sigAction.sa_mask, SIGTRAP);

    // Set the signal handlers, and store the previous signal action into a
    // global array.
    if (sigaction(SIGSEGV, &sigAction, &g_previous_sigaction[SIGSEGV]) != 0)
    {
        abort();
    }

    if (sigaction(SIGFPE, &sigAction, &g_previous_sigaction[SIGFPE]) != 0)
    {
        abort();
    }

    if (sigaction(SIGILL, &sigAction, &g_previous_sigaction[SIGILL]) != 0)
    {
        abort();
    }

    if (sigaction(SIGBUS, &sigAction, &g_previous_sigaction[SIGBUS]) != 0)
    {
        abort();
    }

    if (sigaction(SIGTRAP, &sigAction, &g_previous_sigaction[SIGTRAP]) != 0)
    {
        abort();
    }

    return;
}

// The exception only need to be initialized once per process.
void _oe_initialize_host_exception()
{
    _register_signal_handlers();
}
