// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "syscall_t.h"

/*
 * This file implements the default implementations of syscall-related
 * system ocall wrappers. Each implementation is simply an empty function
 * that returns OE_UNSUPPORTED. If a user does not opt-into these ocalls
 * (via importing the edls), the linker will pick the default implementions
 * (which are weak). If the user opts-into any of the ocalls, the linker will
 * pick the oeedger8r-generated wrapper of the corresponding ocall (which
 * is strong) instead.
 *
 * Note that we need to make the default implementations weak to support
 * selective ocall import. The reason for this is that if the linker picks
 * one of the symbols from an object file, it also pulls the rest of the
 * symbols in the same object file. This behavior causes multiple definition
 * errors when the user wants to selectively import ocalls if the default
 * implementations are strong. For example, the user imports one ocall from
 * epoll.edl. The linker firstly picks the oeedger8r-generated implementation
 * of the ocall. However, when the linker looks up the default implementations
 * of the non-imported ocalls in this object file (hostcalls.o), it also pulls
 * the default implementation of the imported ocall. Because both the default
 * and the oeedger8r-generated implementations are strong, the linker raises the
 * error.
 */

/*
**==============================================================================
**
** ioctl.edl
**
**==============================================================================
*/

/**
 * Declare the prototypes of the following functions to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_syscall_ioctl_ocall(
    int* _retval,
    oe_host_fd_t fd,
    uint64_t request,
    uint64_t arg,
    uint64_t argsize,
    void* argout);

/**
 * Implement the functions and make them as the weak aliases of
 * the public ocall wrappers.
 */
oe_result_t _oe_syscall_ioctl_ocall(
    int* _retval,
    oe_host_fd_t fd,
    uint64_t request,
    uint64_t arg,
    uint64_t argsize,
    void* argout)
{
    OE_UNUSED(_retval);
    OE_UNUSED(fd);
    OE_UNUSED(request);
    OE_UNUSED(arg);
    OE_UNUSED(argsize);
    OE_UNUSED(argout);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_ioctl_ocall, oe_syscall_ioctl_ocall);

/*
**==============================================================================
**
** time.edl
**
**==============================================================================
*/

/**
 * Declare the prototypes of the following functions to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_syscall_nanosleep_ocall(
    int* _retval,
    struct oe_timespec* req,
    struct oe_timespec* rem);

/**
 * Implement the functions and make them as the weak aliases of
 * the public ocall wrappers.
 */
oe_result_t _oe_syscall_nanosleep_ocall(
    int* _retval,
    struct oe_timespec* req,
    struct oe_timespec* rem)
{
    OE_UNUSED(_retval);
    OE_UNUSED(req);
    OE_UNUSED(rem);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_nanosleep_ocall, oe_syscall_nanosleep_ocall);

/*
**==============================================================================
**
** unistd.edl
**
**==============================================================================
*/

/**
 * Declare the prototypes of the following functions to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_syscall_getpid_ocall(int* _retval);
oe_result_t _oe_syscall_getppid_ocall(int* _retval);
oe_result_t _oe_syscall_getpgrp_ocall(int* _retval);
oe_result_t _oe_syscall_getuid_ocall(unsigned int* _retval);
oe_result_t _oe_syscall_geteuid_ocall(unsigned int* _retval);
oe_result_t _oe_syscall_getgid_ocall(unsigned int* _retval);
oe_result_t _oe_syscall_getegid_ocall(unsigned int* _retval);
oe_result_t _oe_syscall_getpgid_ocall(int* _retval, int pid);
oe_result_t _oe_syscall_getgroups_ocall(
    int* _retval,
    size_t size,
    unsigned int* list);

/**
 * Implement the functions and make them as the weak aliases of
 * the public ocall wrappers.
 */
oe_result_t _oe_syscall_getpid_ocall(int* _retval)
{
    OE_UNUSED(_retval);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getpid_ocall, oe_syscall_getpid_ocall);

oe_result_t _oe_syscall_getppid_ocall(int* _retval)
{
    OE_UNUSED(_retval);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getppid_ocall, oe_syscall_getppid_ocall);

oe_result_t _oe_syscall_getpgrp_ocall(int* _retval)
{
    OE_UNUSED(_retval);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getpgrp_ocall, oe_syscall_getpgrp_ocall);

oe_result_t _oe_syscall_getuid_ocall(unsigned int* _retval)
{
    OE_UNUSED(_retval);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getuid_ocall, oe_syscall_getuid_ocall);

oe_result_t _oe_syscall_geteuid_ocall(unsigned int* _retval)
{
    OE_UNUSED(_retval);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_geteuid_ocall, oe_syscall_geteuid_ocall);

oe_result_t _oe_syscall_getgid_ocall(unsigned int* _retval)
{
    OE_UNUSED(_retval);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getgid_ocall, oe_syscall_getgid_ocall);

oe_result_t _oe_syscall_getegid_ocall(unsigned int* _retval)
{
    OE_UNUSED(_retval);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getegid_ocall, oe_syscall_getegid_ocall);

oe_result_t _oe_syscall_getpgid_ocall(int* _retval, int pid)
{
    OE_UNUSED(_retval);
    OE_UNUSED(pid);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getpgid_ocall, oe_syscall_getpgid_ocall);

oe_result_t _oe_syscall_getgroups_ocall(
    int* _retval,
    size_t size,
    unsigned int* list)
{
    OE_UNUSED(_retval);
    OE_UNUSED(size);
    OE_UNUSED(list);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_syscall_getgroups_ocall, oe_syscall_getgroups_ocall);
