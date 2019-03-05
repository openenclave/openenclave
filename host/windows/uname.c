// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/sys/utsname.h>
#include <string.h>
#include <windows.h>
#include "../ocalls.h"

void oe_handle_uname(uint64_t arg_in, uint64_t* arg_out)
{
    struct oe_utsname* out = (struct oe_utsname*)arg_in;

    if (!out)
    {
        if (arg_out)
        {
            *arg_out = OE_EFAULT;
            return;
        }
    }

    memset(out, 0, sizeof(struct oe_utsname));

    /* oe_utsname.sysname */
    strcpy(out->sysname, "Windows");

    /* oe_utsname.nodename */
    GetComputerNameA(out->nodename, sizeof(out->nodename));

    strcpy(out->release, "(none)");
    strcpy(out->machine, "x86_64");

    /* oe_utsname.version*/
    {
        DWORD version = GetVersion();
        DWORD major = (DWORD)(LOBYTE(LOWORD(version)));
        DWORD minor = (DWORD)(HIBYTE(LOWORD(version)));
        snprintf(out->version, sizeof(out->version), "%d.%d", major, minor);
    }

    strcpy(out->__domainname, "(none)");

    if (arg_out)
        *arg_out = 0;
}
