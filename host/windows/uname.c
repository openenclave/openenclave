// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/sys/utsname.h>
#include <string.h>
#include <windows.h>
#include "oe_u.h"

int oe_posix_uname_ocall(struct utsname* buf, int* err)
{
    int ret = -1;
#if defined(NOTYET)
    if (!buf)
    {
        if (err)
            *err = OE_EFAULT;

        goto done;
    }

    memset(buf, 0, sizeof(struct oe_utsname));

    /* oe_utsname.sysname */
    strcpy(buf->sysname, "Windows");

    /* oe_utsname.nodename */
    GetComputerNameA(buf->nodename, sizeof(buf->nodename));

    strcpy(buf->release, "(none)");
    strcpy(buf->machine, "x86_64");

    /* oe_utsname.version*/
    {
        DWORD version = GetVersion();
        DWORD major = (DWORD)(LOBYTE(LOWORD(version)));
        DWORD minor = (DWORD)(HIBYTE(LOWORD(version)));
        snprintf(buf->version, sizeof(buf->version), "%d.%d", major, minor);
    }

    strcpy(buf->__domainname, "(none)");

    ret = 0;

done:
#endif
    return ret;
}
