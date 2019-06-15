// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/stdarg.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/internal/backtrace.h>
#include <openenclave/internal/syscall/device.h>
#include <openenclave/internal/syscall/fdtable.h>
#include <openenclave/internal/syscall/raise.h>
#include <openenclave/internal/trace.h>

int __oe_ioctl(int fd, unsigned long request, uint64_t arg)
{
    int ret = -1;
    oe_fd_t* desc;

    if (!(desc = oe_fdtable_get(fd, OE_FD_TYPE_ANY)))
        OE_RAISE_ERRNO(oe_errno);

    ret = desc->ops.fd.ioctl(desc, request, arg);

done:
    return ret;
}

int oe_ioctl(int fd, unsigned long request, ...)
{
    oe_va_list ap;
    oe_va_start(ap, request);
    int r = __oe_ioctl(fd, request, oe_va_arg(ap, uint64_t));
    oe_va_end(ap);
    return r;
}
