#include <dlfcn.h>
#include <elf.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include "enclave_context.h"
#include "inferior_status.h"

// Function pointer definitions.
typedef long (*OE_PtraceFunc)(
    enum __ptrace_request request,
    pid_t pid,
    void* addr,
    void* data);

typedef pid_t (*OE_WaitpidFunc)(pid_t pid, int* status, int options);

// Original syscall functions.
static OE_PtraceFunc g_system_ptrace = NULL;
static OE_WaitpidFunc g_system_waitpid = NULL;

// Initializer.
__attribute__((constructor)) void init(void);
__attribute__((constructor)) void init()
{
    // Get the ptrace and waitpid syscall function address.
    g_system_ptrace = (OE_PtraceFunc)dlsym(RTLD_NEXT, "ptrace");
    g_system_waitpid = (OE_WaitpidFunc)dlsym(RTLD_NEXT, "waitpid");
}

static long OE_GetGprHandler(pid_t pid, void* addr, void* data)
{
    if (!data)
    {
        return -1;
    }

    // Get the gpr from host thread.
    if (g_system_ptrace(PTRACE_GETREGS, pid, addr, data) == -1)
    {
        return -1;
    }

    // Get the gpr values from enclave thread if the pc is an AEP.
    struct user_regs_struct* regs = (struct user_regs_struct*)data;
    if (OE_IsAEP(pid, regs))
    {
        // rbx has the TCS of enclave thread.
        if (OE_GetEnclaveThreadGpr(pid, (void*)regs->rbx, regs) != 0)
        {
            return -1;
        }
    }

    return 0;
}

static long OE_SetGprHandler(pid_t pid, void* addr, void* data)
{
    if (!data)
    {
        return -1;
    }

    // Get the gpr from host thread.
    struct user_regs_struct aep_regs;
    if (g_system_ptrace(PTRACE_GETREGS, pid, 0, (void*)&aep_regs) == -1)
    {
        return -1;
    }

    // Set the enclave thread gpr if the pc is an AEP.
    if (OE_IsAEP(pid, &aep_regs))
    {
        // rbx has the TCS of enclave thread.
        struct user_regs_struct* regs = (struct user_regs_struct*)data;
        if (OE_SetEnclaveThreadGpr(pid, (void*)aep_regs.rbx, regs) != 0)
        {
            return -1;
        }
        else
        {
            return 0;
        }
    }

    return g_system_ptrace(PTRACE_SETREGS, pid, addr, data);
}

static long OE_GetFprHandler(pid_t pid, void* addr, void* data)
{
    if (!data)
    {
        return -1;
    }

    // Get the gpr from host thread.
    struct user_regs_struct regs;
    if (g_system_ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
    {
        return -1;
    }

    // Get the fpr values from enclave thread if the pc is an AEP.
    if (OE_IsAEP(pid, &regs))
    {
        // rbx has the TCS of enclave thread.
        if (OE_GetEnclaveThreadFpr(
                pid, (void*)regs.rbx, (struct user_fpregs_struct*)data) != 0)
        {
            return -1;
        }
        else
        {
            return 0;
        }
    }

    return g_system_ptrace(PTRACE_GETFPREGS, pid, addr, data);
}

static long OE_SetFprHandler(pid_t pid, void* addr, void* data)
{
    if (!data)
    {
        return -1;
    }

    // Get the gpr from host thread.
    struct user_regs_struct regs;
    if (g_system_ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
    {
        return -1;
    }

    // Set the fpr values to enclave thread if the pc is an AEP.
    if (OE_IsAEP(pid, &regs))
    {
        // rbx has the TCS of enclave thread.
        if (OE_SetEnclaveThreadFpr(
                pid, (void*)regs.rbx, (struct user_fpregs_struct*)data) != 0)
        {
            return -1;
        }
        else
        {
            return 0;
        }
    }

    return g_system_ptrace(PTRACE_GETFPREGS, pid, addr, data);
}

static long OE_GetRegSetHandler(pid_t pid, void* addr, void* data)
{
    if (!data)
    {
        return -1;
    }

    // Get the gpr from host thread.
    struct user_regs_struct regs;
    if (g_system_ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
    {
        return -1;
    }

    // Get the XState values from enclave thread if the pc is an AEP.
    if (OE_IsAEP(pid, &regs))
    {
        unsigned long type = (unsigned long)addr;
        if (NT_X86_XSTATE != type)
        {
            return -1;
        }

        // rbx has the TCS of enclave thread.
        struct iovec* iov = (struct iovec*)data;
        if (iov->iov_base && iov->iov_len &&
            (OE_GetEnclaveThreadXState(
                 pid, (void*)regs.rbx, (void*)iov->iov_base, iov->iov_len) ==
             0))
        {
            return 0;
        }
        else
        {
            return -1;
        }
    }

    return g_system_ptrace(PTRACE_GETREGSET, pid, addr, data);
}

static long OE_SetRegSetHandler(pid_t pid, void* addr, void* data)
{
    if (!data)
    {
        return -1;
    }

    // Get the gpr from host thread.
    struct user_regs_struct regs;
    if (g_system_ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
    {
        return -1;
    }

    // Set the XState values to enclave thread if the pc is an AEP.
    if (OE_IsAEP(pid, &regs))
    {
        unsigned long type = (unsigned long)addr;
        if (NT_X86_XSTATE != type)
        {
            return -1;
        }

        // rbx has the TCS of enclave thread.
        struct iovec* iov = (struct iovec*)data;
        if (iov->iov_base && iov->iov_len &&
            (OE_SetEnclaveThreadXState(
                 pid, (void*)regs.rbx, (void*)iov->iov_base, iov->iov_len) ==
             0))
        {
            return 0;
        }
        else
        {
            return -1;
        }
    }

    return g_system_ptrace(PTRACE_SETREGSET, pid, addr, data);
}

static long OE_SingleStepHandler(pid_t pid, void* addr, void* data)
{
    _OE_TrackInferior(pid);
    _OE_SetInferiorFlags(pid, OE_INFERIOR_SINGLE_STEP);

    return g_system_ptrace(PTRACE_SINGLESTEP, pid, addr, data);
}

// Customized ptrace request handler table.
typedef long (*OE_PtraceRquestHandler)(pid_t, void*, void*);
typedef enum __ptrace_request OE_PtraceRequestType;

struct
{
    OE_PtraceRequestType request_type;
    OE_PtraceRquestHandler request_handler;
} g_request_handlers[] = {
    // GRP requests.
    {PTRACE_GETREGS, OE_GetGprHandler},
    {PTRACE_SETREGS, OE_SetGprHandler},

    // Floating pointer registers requests.
    {PTRACE_GETFPREGS, OE_GetFprHandler},
    {PTRACE_SETFPREGS, OE_SetFprHandler},

    // Extended floating pointer registers requests.
    {PTRACE_GETFPXREGS, OE_GetFprHandler},
    {PTRACE_SETFPXREGS, OE_SetFprHandler},

    // Register set request, can be used to get extended processor
    // states(XState).
    {PTRACE_GETREGSET, OE_GetRegSetHandler},
    {PTRACE_SETREGSET, OE_SetRegSetHandler},

    // Single step request.
    {PTRACE_SINGLESTEP, OE_SingleStepHandler},
};

/*
**==============================================================================
**
** ptrace
**
**      process trace function.
**      Refer to http://man7.org/linux/man-pages/man2/ptrace.2.html
**
**==============================================================================
*/

long ptrace(OE_PtraceRequestType __request, ...)
{
    pid_t pid;
    void* addr;
    void* data;
    va_list ap;

    va_start(ap, __request);
    pid = va_arg(ap, pid_t);
    addr = va_arg(ap, void*);
    data = va_arg(ap, void*);
    va_end(ap);

    // If the request should be handled by the customized handler, calls
    // customer handler.
    for (uint32_t i = 0; i < OE_COUNTOF(g_request_handlers); i++)
    {
        if (__request == g_request_handlers[i].request_type)
        {
            return g_request_handlers[i].request_handler(pid, addr, data);
        }
    }

    // Fall back to ptrace syscall.
    return g_system_ptrace(__request, pid, addr, data);
}

/*
**==============================================================================
**
** waitpid
**
**      waitpid function to wait for process to change state.
**      Refer to http://man7.org/linux/man-pages/man2/waitpid.2.html
**
**==============================================================================
*/

pid_t waitpid(pid_t pid, int* status, int options)
{
    // Get inferior process ID.
    pid_t ret_pid = g_system_waitpid(pid, status, options);
    if (ret_pid == -1 || status == NULL)
    {
        return ret_pid;
    }

    // Remove the inferior info if it is terminated.
    if (WIFEXITED(*status) || WIFSIGNALED(*status))
    {
        _OE_UntrackInferior(ret_pid);
    }

    // Handle the traps.
    if (WIFSTOPPED(*status) && WSTOPSIG(*status) == SIGTRAP)
    {
        int ret;
        long flags;

        // Cleanup the single step flag.
        ret = _OE_GetInferiorFlags(ret_pid, &flags);
        if ((ret == 0) && (flags & OE_INFERIOR_SINGLE_STEP))
        {
            _OE_SetInferiorFlags(ret_pid, (flags & ~OE_INFERIOR_SINGLE_STEP));
        }

        // Fix the register if it is a breakpoint inside enclave.
        struct user_regs_struct regs;
        ret = g_system_ptrace(PTRACE_GETREGS, ret_pid, 0, &regs);
        if (ret == 0 && OE_IsAEP(ret_pid, &regs))
        {
            void* tcs = (void*)regs.rbx;
            if (OE_GetEnclaveThreadGpr(ret_pid, (void*)tcs, &regs) == 0)
            {
                uint8_t bp = 0;
                ret = OE_ReadProcessMemory(
                    ret_pid, (void*)regs.rip, (void*)&bp, 1, NULL);
                if ((ret == 0) && (bp == 0xcc))
                {
                    regs.rip++;
                    OE_SetEnclaveThreadGpr(ret_pid, (void*)tcs, &regs);
                }
            }
        }
    }

    return ret_pid;
}