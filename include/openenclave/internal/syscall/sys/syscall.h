// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_SYS_SYSCALL_H
#define _OE_SYSCALL_SYS_SYSCALL_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

#if defined(__aarch64__)
#include <openenclave/internal/syscall/sys/bits/syscall_aarch64.h>
#elif defined(__x86_64__)
#include <openenclave/internal/syscall/sys/bits/syscall_x86_64.h>
#else
#error "unsupported platform"
#endif

long oe_syscall(long number, ...);

OE_EXTERNC_END

#endif /* _OE_SYSCALL_SYS_SYSCALL_H */
