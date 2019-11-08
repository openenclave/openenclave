// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/internal/syscall/raise.h>
#include <openenclave/internal/syscall/sys/utsname.h>
#include <openenclave/internal/trace.h>
#include "syscall_t.h"

int oe_uname(struct oe_utsname* buf)
{
    int ret = -1;

    if (oe_syscall_uname_ocall(&ret, (struct oe_utsname*)buf) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:

    return ret;
}
