// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYS_UTSNAME_H
#define _OE_SYS_UTSNAME_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/bits/devids.h>

OE_EXTERNC_BEGIN

struct oe_utsname
{
#include <openenclave/corelibc/sys/bits/utsname.h>
};

int oe_uname(struct oe_utsname* buf);

#if defined(OE_NEED_STDC_NAMES)

struct utsname
{
#include <openenclave/corelibc/sys/bits/utsname.h>
};

int uname(struct oe_utsname* buf);

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_SYS_UTSNAME_H */
