// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <openenclave/corelibc/sys/utsname.h>
#include <openenclave/internal/defs.h>
#include <string.h>
#include <sys/utsname.h>
#include "oe_u.h"

int oe_posix_uname_ocall(struct utsname* buf, int* err)
{
    int ret = -1;
    struct oe_utsname* out = (struct oe_utsname*)buf;

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

    ret = uname((struct utsname*)out);

    if (ret == -1)
    {
        if (err)
            *err = errno;
    }

    return ret;
}
