// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_SYSCALL_H
#define _OE_INTERNAL_SYSCALL_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

typedef oe_result_t (*oe_syscall_hook_t)(
    long number,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5,
    long arg6,
    long* ret);

/**
 * Install a hook to intercept syscalls.
 *
 * This function installs a hook to intercept syscalls originating from the
 * MUSL C library. The hook may handle the syscall and return **OE_OK** or
 * it may ignore the syscall and return any other value, causing **libc**
 * to perform the default action for that syscall. By convention, hooks should
 * return **OE_UNSUPPORTED** when ignoring the syscall, although **libc* does
 * not check the hook's return value. Note that only one hook may be installed
 * at a time, so this function replaces any previously installed hook. To
 * uninstall the hook, pass NULL to this function.
 *
 * @param hook the syscall hook.
 */
void oe_register_syscall_hook(oe_syscall_hook_t hook);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_SYSCALL_H */
