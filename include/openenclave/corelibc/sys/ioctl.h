// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYS_IOCTL_H
#define _OE_SYS_IOCTL_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/stdarg.h>

OE_EXTERNC_BEGIN

int oe_ioctl(int fd, unsigned long request, ...);

int oe_ioctl_va(int fd, unsigned long request, oe_va_list ap);

#if defined(OE_NEED_STDC_NAMES)

OE_INLINE int ioctl(int fd, unsigned long request, ...)
{
    oe_va_list ap;
    oe_va_start(ap, request);
    int r = oe_ioctl_va(fd, request, ap);
    oe_va_end(ap);
    return r;
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_SYS_IOCTL_H */
