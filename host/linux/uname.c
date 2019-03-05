// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <openenclave/corelibc/sys/utsname.h>
#include <openenclave/internal/defs.h>
#include <string.h>
#include <sys/utsname.h>
#include "../ocalls.h"

void oe_handle_uname(uint64_t arg_in, uint64_t* arg_out)
{
    struct oe_utsname* out = (struct oe_utsname*)arg_in;

    OE_STATIC_ASSERT(sizeof(struct oe_utsname) == sizeof(struct utsname));
    OE_CHECK_FIELD(struct oe_utsname, struct utsname, sysname);
    OE_CHECK_FIELD(struct oe_utsname, struct utsname, nodename);
    OE_CHECK_FIELD(struct oe_utsname, struct utsname, release);
    OE_CHECK_FIELD(struct oe_utsname, struct utsname, version);
    OE_CHECK_FIELD(struct oe_utsname, struct utsname, machine);
#ifdef _GNU_SOURCE
    OE_CHECK_FIELD(struct oe_utsname, struct utsname, domainname);
#else
    OE_CHECK_FIELD(struct oe_utsname, struct utsname, __domainname);
#endif

    if (uname((struct utsname*)out) != 0)
    {
        if (arg_out)
            *arg_out = (uint64_t)errno;
        return;
    }

    if (arg_out)
        *arg_out = 0;
}
