#include <assert.h>
#include <dlfcn.h>
#include <openenclave/bits/build.h>
#include <openenclave/bits/calls.h>
#include <openenclave/bits/registers.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/trace.h>
#include <openenclave/bits/utils.h>
#include <openenclave/host.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>
#include "asmdefs.h"
#include "enclave.h"

#if !defined(_NSIG) && defined(_SIG_MAXSIG)
#define _NSIG (_SIG_MAXSIG - 1)
#endif

static struct sigaction g_previous_sigaction[_NSIG];

static void _HostSignalHandler(int sigNum, siginfo_t* sigInfo, void* sigData)
{
    ucontext_t* context = (ucontext_t*)sigData;
    uint64_t exitCode = context->uc_mcontext.gregs[REG_RAX];
    uint64_t tcsAddress = context->uc_mcontext.gregs[REG_RBX];
    uint64_t exitAddress = context->uc_mcontext.gregs[REG_RIP];

    // Check if the signal happens inside the enclave.
    if ((exitAddress == (uint64_t)OE_AEP) && (exitCode == ENCLU_ERESUME))
    {
        // Call-in enclave to handle the exception.
        uint64_t arg1 = OE_MakeCallArg1(OE_CODE_ECALL, OE_FUNC_VIRTUAL_EXCEPTION_HANDLER, 0);
        uint64_t arg2 = 0;
        uint64_t arg3 = 0;
        uint64_t arg4 = 0;

        OE_Enter((void*)tcsAddress, OE_AEP, arg1, arg2, &arg3, &arg4, NULL);
        if (arg4 == OE_EXCEPTION_CONTINUE_EXECUTION)
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
        // If not an enclave exception, and no valid previous signal handler is set, raise it again, and let the
        // default signal handler handle it.
        signal(sigNum, SIG_DFL);
        raise(sigNum);
    }
    else
    {
        // If not an enclave exception, and there is old signal handler, we need transfer the signal to the old
        // signal handler;
        if (!(g_previous_sigaction[sigNum].sa_flags & SA_NODEFER))
        {
            sigaddset(&g_previous_sigaction[sigNum].sa_mask, sigNum);
        }

        sigset_t currentSet;
        pthread_sigmask(SIG_SETMASK, &g_previous_sigaction[sigNum].sa_mask, &currentSet);

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

        // If the g_previous_sigaction set SA_RESETHAND, it will break the chain which means
        // g_previous_sigaction->next_old_sigact will not be called. Our signal handler does not
        // responsible for that. We just follow what OS do on SA_RESETHAND.
        if (g_previous_sigaction[sigNum].sa_flags & SA_RESETHAND)
            g_previous_sigaction[sigNum].sa_handler = SIG_DFL;
    }

    return;
}

static void _RegisterSignalHandlers(void)
{
    struct sigaction sigAction;

    // Set the signal handler.
    memset(&sigAction, 0, sizeof(sigAction));
    sigAction.sa_sigaction = _HostSignalHandler;

    // To use sa_sigaction instead of sa_handler, and allow catch the same signal as the one you're currently handling,
    // and automatically restart the system call interrupted the signal.
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

    // Set the signal handlers, and store the previous signal action into a global array.
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
static OE_H_OnceType _enclave_exception_once;

static void _InitializeException(void)
{
    _RegisterSignalHandlers();
}

void _OE_InitializeHostException()
{
    OE_H_Once(&_enclave_exception_once, _InitializeException);
}
