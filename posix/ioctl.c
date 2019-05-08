// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/device.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/stdarg.h>
#include <openenclave/internal/device/device.h>
#include <openenclave/internal/device/fdtable.h>
#include <openenclave/internal/device/raise.h>
#include <openenclave/internal/trace.h>

int __oe_ioctl(int fd, unsigned long request, uint64_t arg)
{
    int ret = -1;
    static const unsigned long _TIOCGWINSZ = 0x5413;

    if (request == _TIOCGWINSZ)
    {
        static const unsigned long _TIOCGWINSZ = 0x5413;

        if (request == _TIOCGWINSZ)
        {
            struct winsize
            {
                unsigned short int ws_row;
                unsigned short int ws_col;
                unsigned short int ws_xpixel;
                unsigned short int ws_ypixel;
            };
            struct winsize* p;

            if (!(p = (struct winsize*)arg))
                OE_RAISE_ERRNO(OE_EINVAL);

            p->ws_row = 24;
            p->ws_col = 80;
            p->ws_xpixel = 0;
            p->ws_ypixel = 0;

            ret = 0;
            goto done;
        }

        ret = -1;
        goto done;
    }
    else
    {
        oe_device_t* device;

        if (!(device = oe_fdtable_get(fd, OE_DEVICE_TYPE_NONE)))
            OE_RAISE_ERRNO(oe_errno);

        if (device->ops.base->ioctl == NULL)
            OE_RAISE_ERRNO(OE_EINVAL);

        // The action routine sets errno
        ret = (*device->ops.base->ioctl)(device, request, arg);
        goto done;
    }

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
