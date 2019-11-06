// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_SYS_UTSNAME_H
#define _OE_SYSCALL_SYS_UTSNAME_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

#define __OE_UTSNAME oe_utsname
#include <openenclave/internal/syscall/sys/bits/utsname.h>
#undef __OE_UTSNAME

int oe_uname(struct oe_utsname* buf);

OE_EXTERNC_END

#endif /* _OE_SYSCALL_SYS_UTSNAME_H */
