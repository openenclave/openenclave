// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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
typedef int64_t (*oe_ptrace_func_t)(
    enum __ptrace_request request,
    pid_t pid,
    void* addr,
    void* data);

typedef pid_t (*oe_waitpid_func_t)(pid_t pid, int* status, int options);

// Original syscall functions.
static oe_ptrace_func_t g_system_ptrace = NULL;
static oe_waitpid_func_t g_system_waitpid = NULL;

// Initializer.
__attribute__((constructor)) void init(void);
__attribute__((constructor)) void init()
{
    // Get the ptrace and waitpid syscall function address.
    g_system_ptrace = (oe_ptrace_func_t)dlsym(RTLD_NEXT, "ptrace");
    g_system_waitpid = (oe_waitpid_func_t)dlsym(RTLD_NEXT, "waitpid");
}

static int64_t oe_get_gpr_handler(pid_t pid, void* addr, void* data)
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
    if (oe_is_aep(pid, regs))
    {
        // rbx has the TCS of enclave thread.
        if (oe_get_enclave_thread_gpr(pid, (void*)regs->rbx, regs) != 0)
        {
            return -1;
        }
    }

    return 0;
}

static int64_t oe_set_gpr_handler(pid_t pid, void* addr, void* data)
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
    if (oe_is_aep(pid, &aep_regs))
    {
        // rbx has the TCS of enclave thread.
        struct user_regs_struct* regs = (struct user_regs_struct*)data;
        if (oe_set_enclave_thread_gpr(pid, (void*)aep_regs.rbx, regs) != 0)
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

static int64_t oe_get_fpr_handler(pid_t pid, void* addr, void* data)
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
    if (oe_is_aep(pid, &regs))
    {
        // rbx has the TCS of enclave thread.
        if (oe_get_enclave_thread_fpr(
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

static int64_t oe_set_fpr_handler(pid_t pid, void* addr, void* data)
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
    if (oe_is_aep(pid, &regs))
    {
        // rbx has the TCS of enclave thread.
        if (oe_set_enclave_thread_fpr(
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

static int64_t oe_get_reg_set_handler(pid_t pid, void* addr, void* data)
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
    if (oe_is_aep(pid, &regs))
    {
        uint64_t type = (uint64_t)addr;
        if (NT_X86_XSTATE != type)
        {
            return -1;
        }

        // rbx has the TCS of enclave thread.
        struct iovec* iov = (struct iovec*)data;
        if (iov->iov_base && iov->iov_len &&
            (oe_get_enclave_thread_xstate(
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

static int64_t oe_set_reg_set_handler(pid_t pid, void* addr, void* data)
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
    if (oe_is_aep(pid, &regs))
    {
        uint64_t type = (uint64_t)addr;
        if (NT_X86_XSTATE != type)
        {
            return -1;
        }

        // rbx has the TCS of enclave thread.
        struct iovec* iov = (struct iovec*)data;
        if (iov->iov_base && iov->iov_len &&
            (oe_set_enclave_thread_xstate(
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

static int64_t oe_single_step_handler(pid_t pid, void* addr, void* data)
{
    oe_track_inferior(pid);
    oe_set_inferior_flags(pid, OE_INFERIOR_SINGLE_STEP);

    return g_system_ptrace(PTRACE_SINGLESTEP, pid, addr, data);
}

// Customized ptrace request handler table.
typedef int64_t (*oe_ptrace_request_handler)(pid_t, void*, void*);
typedef enum __ptrace_request oe_ptrace_request_type;

struct
{
    oe_ptrace_request_type request_type;
    oe_ptrace_request_handler request_handler;
} g_request_handlers[] = {
    // GRP requests.
    {PTRACE_GETREGS, oe_get_gpr_handler},
    {PTRACE_SETREGS, oe_set_gpr_handler},

    // Floating pointer registers requests.
    {PTRACE_GETFPREGS, oe_get_fpr_handler},
    {PTRACE_SETFPREGS, oe_set_fpr_handler},

    // Extended floating pointer registers requests.
    {PTRACE_GETFPXREGS, oe_get_fpr_handler},
    {PTRACE_SETFPXREGS, oe_set_fpr_handler},

    // Register set request, can be used to get extended processor
    // states(XState).
    {PTRACE_GETREGSET, oe_get_reg_set_handler},
    {PTRACE_SETREGSET, oe_set_reg_set_handler},

    // Single step request.
    {PTRACE_SINGLESTEP, oe_single_step_handler},
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

int64_t ptrace(oe_ptrace_request_type __request, ...)
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
        oe_untrack_inferior(ret_pid);
    }

    // Handle the traps.
    if (WIFSTOPPED(*status) && WSTOPSIG(*status) == SIGTRAP)
    {
        long ret;
        int64_t flags;

        // Cleanup the single step flag.
        ret = oe_get_inferior_flags(ret_pid, &flags);
        if ((ret == 0) && (flags & OE_INFERIOR_SINGLE_STEP))
        {
            oe_set_inferior_flags(ret_pid, (flags & ~OE_INFERIOR_SINGLE_STEP));
        }

        // Fix the register if it is a breakpoint inside enclave.
        struct user_regs_struct regs;
        ret = g_system_ptrace(PTRACE_GETREGS, ret_pid, 0, &regs);
        if (ret == 0 && oe_is_aep(ret_pid, &regs))
        {
            void* tcs = (void*)regs.rbx;
            if (oe_get_enclave_thread_gpr(ret_pid, (void*)tcs, &regs) == 0)
            {
                uint8_t bp = 0;
                ret = oe_read_process_memory(
                    ret_pid, (void*)regs.rip, (void*)&bp, 1, NULL);
                if ((ret == 0) && (bp == 0xcc))
                {
                    regs.rip++;
                    oe_set_enclave_thread_gpr(ret_pid, (void*)tcs, &regs);
                }
            }
        }
    }

    return ret_pid;
}
